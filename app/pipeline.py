"""Tarama hattı: keşif, zenginleştirme, derin tarama, güvenlik analizi, diff ve skor."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from sqlmodel import Session, delete, select

from app import notify, settings_store
from app.db import session_scope
from app.models import (
    Device,
    DeviceAlias,
    DeviceEvent,
    Finding,
    Port,
    PresenceSample,
    Scan,
    ScanDiff,
    SecurityScoreHistory,
    Subnet,
    utcnow,
)
from app.netutil import default_gateway, ip_in, is_random_mac
from app.scanner import analysis, devicetype, discovery, nmapxml, ports, router, services, vendor
from app.scanner.security import FindingData, analyze_host

log = logging.getLogger(__name__)

OFFLINE_AFTER_MISSES = 3
NOTIFY_SEVERITIES = {"high", "critical"}


class EventSink:
    """Bir tarama süresince oluşan olayları kaydeder, bildirimleri commit sonrası toplu gönderir."""

    def __init__(self):
        self.pending: list[tuple[str, str, str]] = []

    def event(self, s: Session, device: Device | None, kind: str, message: str, severity: str = "info", notify_: bool = False):
        s.add(DeviceEvent(device_id=device.id if device else None, kind=kind, message=message, severity=severity))
        if notify_:
            title = device.display_name if device else "Ağ"
            self.pending.append((title, message, severity))

    def flush(self):
        notify.send_batch(self.pending)
        self.pending = []


# ------------------------------------------------------------------ yardımcılar


def find_device_by_mac(s: Session, mac: str) -> Device | None:
    alias = s.exec(select(DeviceAlias).where(DeviceAlias.mac == mac)).first()
    return s.get(Device, alias.device_id) if alias else None


def identity_of(d: Device, port_sig: frozenset[int] | None = None) -> analysis.Identity:
    return analysis.Identity(
        device_id=d.id,
        hostname=d.hostname,
        mdns_name=d.mdns_name,
        netbios_name=d.netbios_name,
        port_signature=port_sig or frozenset(),
        is_random_mac=d.is_random_mac,
    )


def port_signatures(s: Session) -> dict[int, frozenset[int]]:
    sig: dict[int, set[int]] = {}
    for p in s.exec(select(Port).where(Port.state == "open")):
        sig.setdefault(p.device_id, set()).add(p.port)
    return {k: frozenset(v) for k, v in sig.items()}


def merge_devices(s: Session, src_id: int, dst_id: int, sink: EventSink | None = None) -> Device:
    """src cihazını dst'ye birleştirir (alias, olay ve varlık geçmişi taşınır)."""
    if src_id == dst_id:
        raise ValueError("Bir cihaz kendisiyle birleştirilemez")
    src, dst = s.get(Device, src_id), s.get(Device, dst_id)
    if not src or not dst:
        raise ValueError("Cihaz bulunamadı")
    for model in (DeviceAlias, DeviceEvent, PresenceSample):
        for row in s.exec(select(model).where(model.device_id == src_id)):
            row.device_id = dst_id
            s.add(row)
    s.execute(delete(Port).where(Port.device_id == src_id))
    s.execute(delete(Finding).where(Finding.device_id == src_id))
    # en güncel bilgiler dst'ye
    if src.last_seen > dst.last_seen:
        dst.mac, dst.ip, dst.online, dst.last_seen, dst.last_rtt_ms = src.mac, src.ip, src.online, src.last_seen, src.last_rtt_ms
        dst.missed_scans = src.missed_scans
    for attr in ("hostname", "mdns_name", "netbios_name", "vendor", "os_guess", "name", "location", "owner", "notes"):
        if not getattr(dst, attr) and getattr(src, attr):
            setattr(dst, attr, getattr(src, attr))
    dst.first_seen = min(dst.first_seen, src.first_seen)
    dst.trusted = dst.trusted or src.trusted
    s.add(dst)
    s.flush()
    s.delete(src)
    if sink:
        sink.event(s, dst, "merged", f"{src.mac or src.ip} adresli kayıt bu cihazla birleştirildi")
    return dst


def split_alias(s: Session, alias_id: int) -> Device:
    """Bir MAC'i cihazdan ayırıp yeni cihaz oluşturur."""
    alias = s.get(DeviceAlias, alias_id)
    if not alias:
        raise ValueError("Alias bulunamadı")
    owner = s.get(Device, alias.device_id)
    others = s.exec(select(DeviceAlias).where(DeviceAlias.device_id == alias.device_id, DeviceAlias.id != alias_id)).all()
    if not others:
        raise ValueError("Cihazın tek MAC adresi ayrılamaz")
    new = Device(mac=alias.mac, is_random_mac=is_random_mac(alias.mac), vendor=vendor.lookup(alias.mac),
                 online=False, first_seen=alias.first_seen, last_seen=alias.last_seen, subnet_id=owner.subnet_id if owner else None)
    s.add(new)
    s.flush()
    alias.device_id = new.id
    s.add(alias)
    if owner and owner.mac == alias.mac:
        latest = max(others, key=lambda a: a.last_seen)
        owner.mac = latest.mac
        s.add(owner)
    return new


def upsert_findings(s: Session, device: Device | None, items: list[FindingData], sink: EventSink, scope_sources: set[str], scope_device_only: bool = True) -> None:
    """Bulguları ekler/günceller; aynı kapsamda bu sefer üretilmeyenleri çözüldü olarak işaretler."""
    now = utcnow()
    dev_part = str(device.id) if device else "net"
    seen_keys: set[str] = set()
    for f in items:
        key = f"{f.rule}:{dev_part}:{f.port if f.port is not None else '-'}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        row = s.exec(select(Finding).where(Finding.key == key)).first()
        if row is None:
            row = Finding(key=key, device_id=device.id if device else None, severity=f.severity, title=f.title,
                          description=f.description, remediation=f.remediation, source=f.source,
                          cves=json.dumps(f.cves), port=f.port)
            s.add(row)
            if not row.ignored:
                sink.event(s, device, "finding", f"{f.title}", f.severity, notify_=f.severity in NOTIFY_SEVERITIES)
        else:
            reopened = row.resolved
            row.severity, row.title, row.description, row.remediation = f.severity, f.title, f.description, f.remediation
            row.cves, row.last_seen, row.resolved = json.dumps(f.cves), now, False
            s.add(row)
            if reopened and not row.ignored:
                sink.event(s, device, "finding", f"Tekrar görüldü: {f.title}", f.severity, notify_=f.severity in NOTIFY_SEVERITIES)
    q = select(Finding).where(Finding.resolved == False, Finding.source.in_(scope_sources))  # noqa: E712
    if scope_device_only:
        q = q.where(Finding.device_id == (device.id if device else None))
    for row in s.exec(q):
        if row.key not in seen_keys:
            row.resolved = True
            s.add(row)


def compute_score(s: Session) -> tuple[int, dict]:
    rows = s.exec(select(Finding).where(Finding.resolved == False, Finding.ignored == False)).all()  # noqa: E712
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return analysis.security_score((r.device_id, r.severity) for r in rows), counts


def record_score(s: Session) -> int:
    score, counts = compute_score(s)
    s.add(SecurityScoreHistory(score=score, finding_counts=json.dumps(counts)))
    return score


def build_snapshot(s: Session) -> dict:
    snap: dict[str, dict] = {}
    ports_by_dev: dict[int, dict[str, str]] = {}
    for p in s.exec(select(Port).where(Port.state == "open")):
        ports_by_dev.setdefault(p.device_id, {})[f"{p.protocol}/{p.port}"] = p.label
    findings_by_dev: dict[int | None, dict] = {}
    for f in s.exec(select(Finding).where(Finding.resolved == False, Finding.ignored == False)):  # noqa: E712
        findings_by_dev.setdefault(f.device_id, {})[f.key] = {"title": f.title, "severity": f.severity}
    for d in s.exec(select(Device)):
        if d.last_deep_scan is None:
            continue
        snap[str(d.id)] = {
            "name": d.display_name,
            "ip": d.ip,
            "os": d.os_guess,
            "ports": ports_by_dev.get(d.id, {}),
            "findings": findings_by_dev.get(d.id, {}),
        }
    if None in findings_by_dev:
        snap["net"] = {"name": "Ağ geneli", "ip": None, "os": None, "ports": {}, "findings": findings_by_dev[None]}
    return snap


# ------------------------------------------------------------------ yönetici


class ScanManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.state: dict = {"running": False}
        self.watchdog = None  # main.py tarafından atanır (ArpDetector beslemek için)

    # ---------------------------------------------------------- durum
    def _set(self, **kw):
        self.state.update(kw)

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    def start_async(self, kind: str, trigger: str = "manual") -> bool:
        if self.busy:
            return False
        target = self.run_deep if kind == "deep" else self.run_quick
        threading.Thread(target=target, kwargs={"trigger": trigger}, daemon=True, name=f"scan-{kind}").start()
        return True

    # ---------------------------------------------------------- hızlı keşif
    def run_quick(self, trigger: str = "schedule") -> int | None:
        if not self._lock.acquire(blocking=False):
            log.info("Tarama zaten çalışıyor, hızlı keşif atlandı")
            return None
        try:
            self._set(running=True, kind="quick", phase="Keşif", done=0, total=0, started=utcnow().isoformat())
            return self._quick(trigger)
        except Exception as exc:
            log.exception("Hızlı keşif başarısız")
            self._set(error=str(exc))
            return None
        finally:
            self._set(running=False, phase="Bitti")
            self._lock.release()

    def _quick(self, trigger: str, scan_kind: str = "quick") -> int:
        sink = EventSink()
        with session_scope() as s:
            scan = Scan(kind=scan_kind, trigger=trigger)
            s.add(scan)
            s.flush()
            scan_id = scan.id
            subnets = s.exec(select(Subnet).where(Subnet.enabled == True)).all()  # noqa: E712

        seen: list[tuple[discovery.SeenHost, Subnet]] = []
        self._set(total=len(subnets))
        for i, sn in enumerate(subnets):
            self._set(phase=f"Keşif: {sn.label} ({sn.cidr})", done=i)
            hosts, method = discovery.sweep(sn.cidr, sn.mode)
            log.info("%s: %d host (%s)", sn.cidr, len(hosts), method)
            seen.extend((h, sn) for h in hosts)

        self._set(phase="İsim çözümleme (DNS, mDNS)")
        rdns = discovery.reverse_dns([h.ip for h, _ in seen])
        mdns = services.mdns_browse(timeout=5.0)
        gw = default_gateway()
        gateway_ip = gw[0] if gw else None
        notify_leave = settings_store.get("notify_on_leave")

        with session_scope() as s:
            sigs = port_signatures(s)
            touched: set[int] = set()
            now = utcnow()
            for h, sn in seen:
                d = self._upsert_seen(s, h, sn, rdns.get(h.ip), mdns.get(h.ip), gateway_ip, sigs, sink, now)
                touched.add(d.id)
                if self.watchdog is not None and h.mac:
                    self.watchdog.detector.table.setdefault(h.ip, h.mac)

            scanned_ids = {sn.id for sn in subnets}
            for d in s.exec(select(Device)):
                if d.id in touched:
                    s.add(PresenceSample(device_id=d.id, ts=now, online=True, rtt_ms=d.last_rtt_ms))
                    continue
                if d.subnet_id not in scanned_ids and not any(ip_in(d.ip, sn.cidr) for sn in subnets):
                    continue
                d.missed_scans += 1
                if d.online and d.missed_scans >= OFFLINE_AFTER_MISSES:
                    d.online = False
                    sink.event(s, d, "left", f"Ağdan ayrıldı ({d.ip})", "info", notify_=notify_leave)
                s.add(d)
                s.add(PresenceSample(device_id=d.id, ts=now, online=False, rtt_ms=None))

            scan = s.get(Scan, scan_id)
            scan.hosts_found = len(seen)
            if scan_kind == "quick":
                scan.status, scan.finished_at = "done", utcnow()
            s.add(scan)
        sink.flush()
        return scan_id

    def _upsert_seen(self, s, h: discovery.SeenHost, sn: Subnet, rdns_name, mdns_info, gateway_ip, sigs, sink: EventSink, now) -> Device:
        d = find_device_by_mac(s, h.mac) if h.mac else s.exec(select(Device).where(Device.ip == h.ip, Device.mac == None)).first()  # noqa: E711
        mdns_name = (mdns_info or {}).get("name")
        is_new = d is None
        if d is None:
            d = Device(mac=h.mac, ip=h.ip, subnet_id=sn.id, is_random_mac=is_random_mac(h.mac),
                       hostname=rdns_name, mdns_name=mdns_name, first_seen=now, last_seen=now)
            s.add(d)
            s.flush()
            if d.is_random_mac:
                existing = [identity_of(x, sigs.get(x.id)) for x in s.exec(select(Device).where(Device.id != d.id))]
                match_id = analysis.find_identity_match(identity_of(d), existing)
                if match_id:
                    target = s.get(Device, match_id)
                    s.add(DeviceAlias(device_id=match_id, mac=h.mac, first_seen=now, last_seen=now))
                    s.flush()
                    s.delete(d)
                    s.flush()
                    target.mac = h.mac
                    sink.event(s, target, "merged", f"Yeni gizli MAC ({h.mac}) bu cihaza bağlandı")
                    d, is_new = target, False
            if is_new and h.mac:
                s.add(DeviceAlias(device_id=d.id, mac=h.mac, first_seen=now, last_seen=now))
        elif h.mac:
            alias = s.exec(select(DeviceAlias).where(DeviceAlias.mac == h.mac)).first()
            if alias:
                alias.last_seen = now
                s.add(alias)
            d.mac = h.mac

        if not is_new and d.ip and d.ip != h.ip:
            sink.event(s, d, "ip_changed", f"IP değişti: {d.ip} → {h.ip}")
        if not is_new and not d.online:
            sink.event(s, d, "returned", f"Ağa geri döndü ({h.ip})")

        d.ip = h.ip
        d.subnet_id = sn.id
        d.online, d.missed_scans, d.last_seen = True, 0, now
        d.last_rtt_ms = h.rtt_ms
        d.is_gateway = bool(gateway_ip and h.ip == gateway_ip)
        if rdns_name:
            d.hostname = rdns_name
        if mdns_info:
            d.mdns_name = mdns_name or d.mdns_name
            d.mdns_services = json.dumps(mdns_info.get("services", []))
        if not d.vendor:
            d.vendor = vendor.lookup(d.mac) or h.nmap_vendor
        d.device_type = devicetype.classify(
            vendor=d.vendor, os_guess=d.os_guess, ports=set(sigs.get(d.id, frozenset())),
            mdns_services=d.mdns(), ssdp=d.ssdp(), hostname=d.mdns_name or d.hostname or d.netbios_name, is_gateway=d.is_gateway,
        )
        s.add(d)

        if is_new:
            label = d.vendor or ("Gizli (rastgele) MAC" if d.is_random_mac else "bilinmeyen üretici")
            sink.event(s, d, "joined", f"Yeni cihaz: {h.ip} / {h.mac or 'MAC yok'} ({label})", "medium", notify_=not d.trusted)
        return d

    # ---------------------------------------------------------- derin tarama
    def run_deep(self, trigger: str = "schedule") -> int | None:
        if not self._lock.acquire(blocking=False):
            log.info("Tarama zaten çalışıyor, derin tarama atlandı")
            return None
        scan_id = None
        try:
            self._set(running=True, kind="deep", phase="Keşif", done=0, total=0, started=utcnow().isoformat(), error=None)
            scan_id = self._quick(trigger, scan_kind="deep")
            self._deep(scan_id)
            return scan_id
        except Exception as exc:
            log.exception("Derin tarama başarısız")
            self._set(error=str(exc))
            if scan_id:
                with session_scope() as s:
                    scan = s.get(Scan, scan_id)
                    scan.status, scan.error, scan.finished_at = "failed", str(exc)[:500], utcnow()
                    s.add(scan)
            return None
        finally:
            self._set(running=False, phase="Bitti")
            self._lock.release()

    def _deep(self, scan_id: int) -> None:
        sink = EventSink()
        cfg = settings_store.all_settings()
        with session_scope() as s:
            targets = [(d.id, d.ip, d.is_gateway) for d in s.exec(select(Device).where(Device.online == True, Device.ip != None))]  # noqa: E711,E712

        self._set(phase="SSDP / UPnP keşfi", done=0, total=len(targets))
        ssdp_devices = services.ssdp_discover()

        self._set(phase="Port, servis ve işletim sistemi taraması")
        results: dict[int, nmapxml.HostResult | None] = {}
        with ThreadPoolExecutor(max_workers=max(1, cfg["scan_concurrency"])) as pool:
            futs = {
                pool.submit(ports.scan_host, ip, cfg["top_ports"], cfg["host_timeout_min"], cfg["enable_vulners"]): did
                for did, ip, _ in targets
            }
            for i, fut in enumerate(as_completed(futs), 1):
                results[futs[fut]] = fut.result()
                self._set(done=i)

        self._set(phase="Güvenlik analizi")
        with session_scope() as s:
            now = utcnow()
            for did, ip, _ in targets:
                d = s.get(Device, did)
                hr = results.get(did)
                if d is None or hr is None:
                    continue
                self._apply_host_result(s, d, hr, ssdp_devices.get(ip), sink, now)

            self._set(phase="Router / UPnP denetimi")
            self._router_audit(s, ssdp_devices, sink)

            self._merge_by_port_signature(s, sink)

            self._set(phase="Fark ve skor hesaplama")
            snap = build_snapshot(s)
            prev = s.exec(
                select(Scan).where(Scan.kind == "deep", Scan.status == "done", Scan.id != scan_id).order_by(Scan.id.desc())
            ).first()
            changes = analysis.diff_snapshots(json.loads(prev.snapshot) if prev else {}, snap) if prev else []
            s.add(ScanDiff(scan_id=scan_id, prev_scan_id=prev.id if prev else None, changes=json.dumps(changes), change_count=len(changes)))
            for c in changes:
                if c["kind"] == "port_opened":
                    dev = s.get(Device, int(c["device"])) if c["device"].isdigit() else None
                    sink.event(s, dev, "port_opened", c["detail"], "medium", notify_=True)
                elif c["kind"] == "port_closed":
                    dev = s.get(Device, int(c["device"])) if c["device"].isdigit() else None
                    sink.event(s, dev, "port_closed", c["detail"])
            score = record_score(s)
            scan = s.get(Scan, scan_id)
            scan.snapshot = json.dumps(snap)
            scan.status, scan.finished_at = "done", utcnow()
            s.add(scan)
            log.info("Derin tarama bitti: %d cihaz, %d değişiklik, skor %d", len(targets), len(changes), score)
        sink.flush()

    def _apply_host_result(self, s: Session, d: Device, hr: nmapxml.HostResult, ssdp_dev, sink: EventSink, now) -> None:
        s.execute(delete(Port).where(Port.device_id == d.id))
        for p in hr.ports:
            if p.state not in ("open", "open|filtered"):
                continue
            s.add(Port(device_id=d.id, port=p.port, protocol=p.protocol, state=p.state, service=p.service,
                       product=p.product, version=p.version, extra=p.extra, tls=p.tunnel == "ssl" or p.service == "https"))
        if hr.os_guess:
            d.os_guess = hr.os_guess + (f" ({hr.os_accuracy}%)" if hr.os_accuracy else "")
        nb = nmapxml.netbios_name(hr)
        if nb:
            d.netbios_name = nb
        if hr.hostname and not d.hostname:
            d.hostname = hr.hostname
        if not d.vendor and hr.vendor:
            d.vendor = hr.vendor
        if ssdp_dev is not None:
            info = dict(ssdp_dev.description)
            if ssdp_dev.server:
                info["server"] = ssdp_dev.server
            d.ssdp_info = json.dumps(info)
        d.device_type = devicetype.classify(
            vendor=d.vendor, os_guess=hr.os_guess, os_type=hr.os_class.get("type"), ports={p.port for p in hr.open_ports},
            mdns_services=d.mdns(), ssdp=d.ssdp(), hostname=d.mdns_name or d.hostname or d.netbios_name, is_gateway=d.is_gateway,
        )
        d.last_deep_scan = now
        s.add(d)
        upsert_findings(s, d, analyze_host(hr, is_gateway=d.is_gateway), sink, scope_sources={"rule", "nse"})

    def _router_audit(self, s: Session, ssdp_devices: dict, sink: EventSink) -> None:
        try:
            audit = router.audit(ssdp_devices)
        except Exception:
            log.exception("Router denetimi başarısız")
            return
        settings_store_payload = {
            "igd_found": audit.igd_found, "igd_ip": audit.igd_ip, "model": audit.model, "external_ip": audit.external_ip,
            "mappings": [m.__dict__ for m in audit.mappings], "error": audit.error, "ts": utcnow().isoformat(),
        }
        grouped: dict[int | None, list[FindingData]] = {}
        for f, ip in router.audit_findings(audit):
            dev = s.exec(select(Device).where(Device.ip == ip)).first() if ip else None
            if dev is None and f.rule == "upnp-enabled":
                dev = s.exec(select(Device).where(Device.is_gateway == True)).first()  # noqa: E712
            grouped.setdefault(dev.id if dev else None, []).append(f)
        for dev_id, items in grouped.items():
            dev = s.get(Device, dev_id) if dev_id else None
            upsert_findings(s, dev, items, sink, scope_sources={"router"}, scope_device_only=True)
        # artık hiç yönlendirme/UPnP yoksa tüm router bulgularını kapat
        live = {f"{f.rule}:{d if d else 'net'}:{f.port if f.port is not None else '-'}" for d, items in grouped.items() for f in items}
        for row in s.exec(select(Finding).where(Finding.source == "router", Finding.resolved == False)):  # noqa: E712
            if row.key not in live:
                row.resolved = True
                s.add(row)
        settings_store_set(s, "router_audit", json.dumps(settings_store_payload))

    def _merge_by_port_signature(self, s: Session, sink: EventSink) -> None:
        """Yeni görülen rastgele MAC'li cihazları, çevrimdışı eski kayıtlarla port imzası/isimle eşleştirir."""
        sigs = port_signatures(s)
        cutoff = utcnow() - timedelta(days=1)
        fresh = s.exec(select(Device).where(Device.is_random_mac == True, Device.first_seen >= cutoff)).all()  # noqa: E712
        for d in fresh:
            offline = [identity_of(x, sigs.get(x.id)) for x in s.exec(select(Device).where(Device.online == False, Device.id != d.id))]  # noqa: E712
            match_id = analysis.find_identity_match(identity_of(d, sigs.get(d.id)), offline)
            if match_id:
                merge_devices(s, d.id, match_id, sink)


def settings_store_set(s: Session, key: str, value: str) -> None:
    from app.models import Setting

    row = s.get(Setting, key) or Setting(key=key)
    row.value = value
    s.add(row)


manager = ScanManager()
