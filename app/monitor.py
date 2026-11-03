"""ARP spoofing / rogue DHCP izleyicisini uygulama veritabanı ve bildirimlerle bağlar."""

from __future__ import annotations

import json
import logging

from sqlmodel import select

from app import settings_store
from app.db import session_scope
from app.models import Device, Finding, utcnow
from app.netutil import default_gateway
from app.pipeline import EventSink, manager
from app.scanner.watchdog import Alert, ArpDetector, ArpWatcher, dhcp_probe, evaluate_dhcp_offers

log = logging.getLogger(__name__)


class WatchdogService:
    def __init__(self):
        self.watcher: ArpWatcher | None = None
        self.detector: ArpDetector | None = None

    def _build_detector(self) -> ArpDetector:
        gw = default_gateway()
        gateway_ip = gw[0] if gw else None
        gateway_mac = settings_store.get_raw("gateway_mac") or None
        known: dict[str, str] = {}
        with session_scope() as s:
            for d in s.exec(select(Device).where(Device.online == True, Device.mac != None)):  # noqa: E711,E712
                if d.ip:
                    known[d.ip] = d.mac
                if d.is_gateway and not gateway_mac:
                    gateway_mac = d.mac
        if gateway_mac:
            settings_store.set_raw("gateway_mac", gateway_mac)
        return ArpDetector(gateway_ip, gateway_mac, known)

    def start(self) -> bool:
        if self.watcher and self.watcher.running:
            return True
        self.detector = self._build_detector()
        gw = default_gateway()
        self.watcher = ArpWatcher(self.detector, self.handle_alert, iface=gw[1] if gw else None)
        manager.watchdog = self.watcher
        return self.watcher.start()

    def stop(self) -> None:
        if self.watcher:
            self.watcher.stop()
        manager.watchdog = None

    @property
    def running(self) -> bool:
        return bool(self.watcher and self.watcher.running)

    def accept_gateway_mac(self, mac: str) -> None:
        settings_store.set_raw("gateway_mac", mac)
        if self.detector:
            self.detector.accept_gateway_mac(mac)
        with session_scope() as s:
            for f in s.exec(select(Finding).where(Finding.source == "watchdog", Finding.title.contains("ARP"), Finding.resolved == False)):  # noqa: E712
                f.resolved = True
                s.add(f)

    def handle_alert(self, alert: Alert) -> None:
        sink = EventSink()
        with session_scope() as s:
            device = s.exec(select(Device).where(Device.ip == alert.ip)).first() if alert.ip else None
            if alert.kind == "ip_mac_changed":
                sink.event(s, device, alert.kind, alert.message, alert.severity)
                return
            key = f"{alert.kind}:net:{alert.mac or alert.ip or '-'}"
            row = s.exec(select(Finding).where(Finding.key == key)).first()
            title = "Olası ARP spoofing saldırısı" if alert.kind == "arp_spoof" else "Sahte (rogue) DHCP sunucusu"
            remediation = (
                "Ağdaki tanımadığınız cihazları kontrol edin; saldırgan MAC adresini router'da engelleyin. "
                "Router'ı değiştirdiyseniz Ayarlar sayfasından yeni ağ geçidi MAC'ini onaylayın."
                if alert.kind == "arp_spoof"
                else "Ağa bağlı ikinci bir router/erişim noktası DHCP dağıtıyor olabilir; o cihazda DHCP'yi kapatın."
            )
            if row is None:
                s.add(Finding(key=key, device_id=None, severity=alert.severity, title=title, description=alert.message,
                              remediation=remediation, source="watchdog"))
            else:
                row.last_seen, row.resolved, row.description = utcnow(), False, alert.message
                s.add(row)
            sink.event(s, device, alert.kind, alert.message, alert.severity, notify_=True)
        sink.flush()

    def probe_dhcp(self) -> dict:
        gw = default_gateway()
        try:
            offers = dhcp_probe(iface=gw[1] if gw else None)
        except Exception as exc:
            log.warning("DHCP yoklaması başarısız: %s", exc)
            result = {"ts": utcnow().isoformat(), "error": str(exc), "offers": []}
            settings_store.set_raw("dhcp_probe", json.dumps(result))
            return result
        expected = settings_store.get_raw("dhcp_server_known") or None
        servers = sorted({o["server_id"] for o in offers if o.get("server_id")})
        if not expected and len(servers) == 1:
            settings_store.set_raw("dhcp_server_known", servers[0])
            expected = servers[0]
        for alert in evaluate_dhcp_offers(offers, expected):
            self.handle_alert(alert)
        if len(servers) == 1 and servers[0] == expected:
            with session_scope() as s:
                for f in s.exec(select(Finding).where(Finding.key.startswith("rogue_dhcp:"), Finding.resolved == False)):  # noqa: E712
                    f.resolved = True
                    s.add(f)
        result = {"ts": utcnow().isoformat(), "offers": offers, "expected": expected}
        settings_store.set_raw("dhcp_probe", json.dumps(result))
        return result


watchdog_service = WatchdogService()
