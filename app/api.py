"""REST API."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlmodel import Session, delete, select

from app import i18n, notify, scheduler, settings_store
from app.db import get_session
from app.models import (
    Device,
    DeviceAlias,
    DeviceEvent,
    Finding,
    MergeSuggestion,
    Port,
    PresenceSample,
    Scan,
    ScanDiff,
    SecurityScoreHistory,
    Subnet,
    iso,
    utcnow,
)
from app.monitor import watchdog_service
from app.pipeline import build_snapshot, compute_score, manager, merge_devices, pending_suggestions, split_alias
from app.scanner import analysis, devicetype

router = APIRouter(prefix="/api")


# ------------------------------------------------------------------ serileştirme
def err(status: int, key: str, /, **params) -> HTTPException:
    """Etkin dilde hata mesajı."""
    return HTTPException(status, i18n.t(key, **params))


def device_dict(d: Device, ports_count: int = 0, worst: str | None = None, suggestions: int = 0) -> dict:
    return {
        "id": d.id,
        "name": d.display_name,
        "custom_name": d.name,
        "ip": d.ip,
        "mac": d.mac,
        "vendor": d.vendor,
        "hostname": d.hostname,
        "mdns_name": d.mdns_name,
        "netbios_name": d.netbios_name,
        "dhcp_hostname": d.dhcp_hostname,
        "os_family": d.os_family,
        "os_family_label": i18n.t(f"os.{d.os_family}") if d.os_family else None,
        "os": d.os_guess,
        "type": d.device_type,
        "type_label": devicetype.label(d.device_type),
        "icon": devicetype.icon(d.device_type),
        "subnet_id": d.subnet_id,
        "online": d.online,
        "trusted": d.trusted,
        "is_gateway": d.is_gateway,
        "is_random_mac": d.is_random_mac,
        "archived": d.archived,
        "pending_suggestions": suggestions,
        "location": d.location,
        "owner": d.owner,
        "notes": d.notes,
        "rtt_ms": d.last_rtt_ms,
        "first_seen": iso(d.first_seen),
        "last_seen": iso(d.last_seen),
        "last_deep_scan": iso(d.last_deep_scan),
        "open_ports": ports_count,
        "worst_severity": worst,
    }


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "device_id": f.device_id, "severity": f.severity,
        "title": i18n.finding_text(f.msg_id, f.params, "title", f.title),
        "description": i18n.finding_text(f.msg_id, f.params, "desc", f.description),
        "remediation": i18n.finding_text(f.msg_id, f.params, "fix", f.remediation),
        "source": f.source, "port": f.port, "cves": f.cve_list(),
        "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen),
        "resolved": f.resolved, "ignored": f.ignored,
    }


def event_dict(e: DeviceEvent) -> dict:
    return {"ts": iso(e.ts), "kind": e.kind, "kind_label": i18n.t(f"evk.{e.kind}") if i18n.has(f"evk.{e.kind}") else e.kind,
            "severity": e.severity, "message": i18n.event_text(e.kind, e.params, e.message), "device_id": e.device_id}


def suggestion_dict(sg: MergeSuggestion, s: Session) -> dict:
    dev, cand = s.get(Device, sg.device_id), s.get(Device, sg.candidate_id)
    reasons = json.loads(sg.reasons or "[]")
    return {
        "id": sg.id, "device_id": sg.device_id, "candidate_id": sg.candidate_id, "score": sg.score, "status": sg.status,
        "device_name": dev.display_name if dev else None, "candidate_name": cand.display_name if cand else None,
        "reasons": reasons, "reason_labels": [i18n.t(f"reason.{r}") for r in reasons if i18n.has(f"reason.{r}")],
        "created_at": iso(sg.created_at),
    }


def device_summaries(s: Session, include_archived: bool = False) -> list[dict]:
    port_counts: dict[int, int] = {}
    for p in s.exec(select(Port)):
        port_counts[p.device_id] = port_counts.get(p.device_id, 0) + 1
    worst: dict[int, str] = {}
    for f in s.exec(select(Finding).where(Finding.resolved == False, Finding.ignored == False)):  # noqa: E712
        if f.device_id is None:
            continue
        cur = worst.get(f.device_id)
        if cur is None or analysis.severity_rank(f.severity) > analysis.severity_rank(cur):
            worst[f.device_id] = f.severity
    sugg: dict[int, int] = {}
    for sg in pending_suggestions(s):
        for did in (sg.device_id, sg.candidate_id):
            sugg[did] = sugg.get(did, 0) + 1
    from app.netutil import ip_sort_key

    q = select(Device) if include_archived else select(Device).where(Device.archived == False)  # noqa: E712
    devices = sorted(s.exec(q).all(), key=lambda d: (d.archived, not d.online, ip_sort_key(d.ip)))
    return [device_dict(d, port_counts.get(d.id, 0), worst.get(d.id), sugg.get(d.id, 0)) for d in devices]


def presence_buckets(s: Session, device_id: int, hours: int = 24, buckets: int = 96) -> dict:
    since = utcnow() - timedelta(hours=hours)
    samples = s.exec(
        select(PresenceSample).where(PresenceSample.device_id == device_id, PresenceSample.ts >= since).order_by(PresenceSample.ts)
    ).all()
    width = timedelta(hours=hours) / buckets
    out = [None] * buckets
    rtts: list[float] = []
    for smp in samples:
        idx = min(buckets - 1, int((smp.ts - since) / width))
        out[idx] = True if smp.online or out[idx] else False
        if smp.rtt_ms is not None:
            rtts.append(smp.rtt_ms)
    total = len(samples)
    online = sum(1 for x in samples if x.online)
    return {
        "hours": hours,
        "since": iso(since),
        "buckets": out,
        "uptime_pct": round(online * 100 / total, 1) if total else None,
        "samples": total,
        "rtt_avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "rtt_max": round(max(rtts), 2) if rtts else None,
        "rtt_series": [[iso(smp.ts), smp.rtt_ms] for smp in samples if smp.rtt_ms is not None][-300:],
    }


# ------------------------------------------------------------------ genel
@router.get("/health")
def health():
    return {"status": "ok", "scan_running": manager.busy, "watchdog": watchdog_service.running}


# ------------------------------------------------------------------ cihazlar
@router.get("/devices")
def list_devices(q: Optional[str] = None, subnet_id: Optional[int] = None, online: Optional[bool] = None,
                 include_archived: bool = False, s: Session = Depends(get_session)):
    items = device_summaries(s, include_archived)
    if q:
        ql = q.lower()
        items = [d for d in items if any(ql in str(v).lower() for v in (d["name"], d["ip"], d["mac"], d["vendor"], d["hostname"], d["type_label"], d["location"]) if v)]
    if subnet_id is not None:
        items = [d for d in items if d["subnet_id"] == subnet_id]
    if online is not None:
        items = [d for d in items if d["online"] == online]
    return items


def _get_device(s: Session, device_id: int) -> Device:
    d = s.get(Device, device_id)
    if not d:
        raise err(404, "err.device_not_found")
    return d


@router.get("/devices/{device_id}")
def get_device(device_id: int, s: Session = Depends(get_session)):
    d = _get_device(s, device_id)
    ports = s.exec(select(Port).where(Port.device_id == device_id).order_by(Port.port)).all()
    findings = s.exec(select(Finding).where(Finding.device_id == device_id).order_by(Finding.resolved, Finding.id.desc())).all()
    aliases = s.exec(select(DeviceAlias).where(DeviceAlias.device_id == device_id).order_by(DeviceAlias.last_seen.desc())).all()
    events = s.exec(select(DeviceEvent).where(DeviceEvent.device_id == device_id).order_by(DeviceEvent.ts.desc()).limit(100)).all()
    return device_dict(d, len(ports)) | {
        "ports": [p.model_dump() | {"label": p.label} for p in ports],
        "findings": [finding_dict(f) for f in findings],
        "aliases": [{"id": a.id, "mac": a.mac, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen)} for a in aliases],
        "events": [event_dict(e) for e in events],
        "suggestions": [suggestion_dict(sg, s) for sg in pending_suggestions(s, device_id)],
        "mdns_services": d.mdns(),
        "ssdp": d.ssdp(),
    }


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    trusted: Optional[bool] = None
    device_type: Optional[str] = None


@router.patch("/devices/{device_id}")
def update_device(device_id: int, body: DeviceUpdate, s: Session = Depends(get_session)):
    d = _get_device(s, device_id)
    data = body.model_dump(exclude_unset=True)
    if "device_type" in data and data["device_type"] not in devicetype.TYPES:
        raise err(400, "err.bad_type")
    for k, v in data.items():
        setattr(d, k, (v.strip() or None) if isinstance(v, str) else v)
    s.add(d)
    s.commit()
    return device_dict(d)


@router.delete("/devices/{device_id}")
def delete_device(device_id: int, s: Session = Depends(get_session)):
    d = _get_device(s, device_id)
    for model in (DeviceAlias, Port, Finding, PresenceSample, DeviceEvent):
        s.execute(delete(model).where(model.device_id == device_id))
    s.execute(delete(MergeSuggestion).where((MergeSuggestion.device_id == device_id) | (MergeSuggestion.candidate_id == device_id)))
    s.delete(d)
    s.commit()
    return {"ok": True}


class MergeBody(BaseModel):
    target_id: int


@router.post("/devices/{device_id}/merge")
def merge(device_id: int, body: MergeBody, s: Session = Depends(get_session)):
    try:
        dst = merge_devices(s, device_id, body.target_id)
    except ValueError as exc:
        raise err(400, str(exc)) from exc
    s.commit()
    return device_dict(dst)


@router.post("/aliases/{alias_id}/split")
def split(alias_id: int, s: Session = Depends(get_session)):
    try:
        new = split_alias(s, alias_id)
    except ValueError as exc:
        raise err(400, str(exc)) from exc
    s.commit()
    return device_dict(new)


@router.get("/devices/{device_id}/presence")
def presence(device_id: int, hours: int = 24, s: Session = Depends(get_session)):
    _get_device(s, device_id)
    hours = max(1, min(hours, 24 * 30))
    return presence_buckets(s, device_id, hours, 96 if hours <= 24 else min(168, hours))


# ------------------------------------------------------------------ taramalar
class ScanRequest(BaseModel):
    kind: str = "deep"


@router.post("/scans")
def start_scan(body: ScanRequest):
    if body.kind not in ("quick", "deep"):
        raise err(400, "err.bad_kind")
    if not manager.start_async(body.kind, trigger="manual"):
        raise err(409, "err.scan_running")
    return {"started": True, "kind": body.kind}


@router.get("/scans/status")
def scan_status():
    state = dict(manager.state)
    state["phase"] = i18n.t(state.get("phase") or "phase.done", **(state.get("phase_params") or {}))
    return state | {"running": manager.busy, "next_runs": scheduler.next_runs()}


@router.get("/scans")
def list_scans(kind: Optional[str] = None, limit: int = 50, s: Session = Depends(get_session)):
    q = select(Scan).order_by(Scan.id.desc()).limit(min(limit, 500))
    if kind:
        q = q.where(Scan.kind == kind)
    diffs = {d.scan_id: d.change_count for d in s.exec(select(ScanDiff))}
    return [
        {"id": sc.id, "kind": sc.kind, "trigger": sc.trigger, "status": sc.status, "hosts_found": sc.hosts_found,
         "started_at": iso(sc.started_at), "finished_at": iso(sc.finished_at),
         "error": sc.error, "changes": diffs.get(sc.id)}
        for sc in s.exec(q)
    ]


@router.get("/scans/{scan_id}/export.json")
def export_scan(scan_id: int, s: Session = Depends(get_session)):
    sc = s.get(Scan, scan_id)
    if not sc:
        raise err(404, "err.scan_not_found")
    diff = s.exec(select(ScanDiff).where(ScanDiff.scan_id == scan_id)).first()
    payload = {
        "id": sc.id, "kind": sc.kind, "started_at": iso(sc.started_at),
        "finished_at": iso(sc.finished_at), "status": sc.status,
        "hosts_found": sc.hosts_found, "snapshot": json.loads(sc.snapshot or "{}"),
        "changes": json.loads(diff.changes) if diff else [],
    }
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'})


@router.get("/diff")
def diff(a: Optional[int] = None, b: Optional[int] = None, s: Session = Depends(get_session)):
    """a: eski tarama, b: yeni tarama (b boşsa güncel durum)."""
    deep = s.exec(select(Scan).where(Scan.kind == "deep", Scan.status == "done").order_by(Scan.id.desc())).all()
    if not deep:
        return {"a": None, "b": None, "changes": []}
    newer = next((x for x in deep if x.id == b), None) if b else deep[0]
    if newer is None:
        raise err(404, "err.scan_not_found")
    older = next((x for x in deep if x.id == a), None) if a else next((x for x in deep if x.id < newer.id), None)
    if older is None:
        return {"a": None, "b": newer.id, "changes": []}
    changes = analysis.diff_snapshots(json.loads(older.snapshot or "{}"), json.loads(newer.snapshot or "{}"))
    return {"a": older.id, "b": newer.id, "changes": changes}


# ------------------------------------------------------------------ bulgular & skor
@router.get("/findings")
def list_findings(include_resolved: bool = False, s: Session = Depends(get_session)):
    q = select(Finding)
    if not include_resolved:
        q = q.where(Finding.resolved == False)  # noqa: E712
    rows = sorted(s.exec(q).all(), key=lambda f: (f.ignored, -analysis.severity_rank(f.severity), f.id))
    return [finding_dict(f) for f in rows]


class IgnoreBody(BaseModel):
    ignored: bool = True


@router.post("/findings/{finding_id}/ignore")
def ignore_finding(finding_id: int, body: IgnoreBody, s: Session = Depends(get_session)):
    f = s.get(Finding, finding_id)
    if not f:
        raise err(404, "err.finding_not_found")
    f.ignored = body.ignored
    s.add(f)
    s.commit()
    return finding_dict(f)


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int, s: Session = Depends(get_session)):
    f = s.get(Finding, finding_id)
    if not f:
        raise err(404, "err.finding_not_found")
    f.resolved = True
    s.add(f)
    s.commit()
    return finding_dict(f)


@router.get("/score")
def score(days: int = 30, s: Session = Depends(get_session)):
    current, counts = compute_score(s)
    since = utcnow() - timedelta(days=days)
    hist = s.exec(select(SecurityScoreHistory).where(SecurityScoreHistory.ts >= since).order_by(SecurityScoreHistory.ts)).all()
    grade, label_key = analysis.score_grade(current)
    return {"score": current, "grade": grade, "label": i18n.t(label_key), "counts": counts,
            "history": [{"ts": iso(h.ts), "score": h.score} for h in hist]}


# ------------------------------------------------------------------ harita
@router.get("/map")
def network_map(s: Session = Depends(get_session)):
    subnets = s.exec(select(Subnet)).all()
    devices = device_summaries(s)
    gateway = next((d for d in devices if d["is_gateway"]), None)
    return {
        "gateway": gateway,
        "subnets": [{"id": sn.id, "cidr": sn.cidr, "label": sn.label} for sn in subnets],
        "devices": devices,
    }


# ------------------------------------------------------------------ dışa aktarma
EXPORT_FIELDS = ["id", "name", "ip", "mac", "vendor", "hostname", "type_label", "os", "online", "trusted", "location", "owner",
                 "open_ports", "worst_severity", "first_seen", "last_seen"]


@router.get("/export/devices.json")
def export_json(s: Session = Depends(get_session)):
    items = device_summaries(s)
    ports: dict[int, list] = {}
    for p in s.exec(select(Port)):
        ports.setdefault(p.device_id, []).append({"port": p.port, "protocol": p.protocol, "service": p.label})
    for d in items:
        d["ports"] = ports.get(d["id"], [])
    return JSONResponse(items, headers={"Content-Disposition": 'attachment; filename="devices.json"'})


@router.get("/export/devices.csv")
def export_csv(s: Session = Depends(get_session)):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    w.writeheader()
    for d in device_summaries(s):
        w.writerow(d)
    return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="devices.csv"'})


# ------------------------------------------------------------------ ayarlar
@router.get("/settings")
def get_settings_api():
    return settings_store.all_settings()


@router.put("/settings")
def put_settings(values: dict):
    try:
        result = settings_store.update(values)
    except (ValueError, TypeError) as exc:
        raise err(400, "err.bad_setting", key=str(exc).split(":")[0]) from exc
    if scheduler.scheduler.running:
        scheduler.configure()
    if "enable_watchdog" in values:
        if result["enable_watchdog"]:
            watchdog_service.start()
        else:
            watchdog_service.stop()
    return result


class TestNotification(BaseModel):
    urls: Optional[str] = None


@router.post("/settings/test-notification")
def test_notification(body: TestNotification):
    urls = settings_store.apprise_url_list(body.urls) if body.urls is not None else None
    if urls is not None and not urls:
        raise err(400, "err.no_urls")
    ok = notify.send(i18n.t("notify.test_title"), i18n.t("notify.test_body"), "info", urls=urls, background=False)
    if not ok:
        raise err(502, "err.notify_failed")
    return {"ok": True}


class SubnetBody(BaseModel):
    cidr: str
    label: str = "Ağ"
    enabled: bool = True
    mode: str = "auto"


def _validate_subnet(body: SubnetBody) -> str:
    try:
        net = ipaddress.IPv4Network(body.cidr.strip(), strict=False)
    except ValueError as exc:
        raise err(400, "err.bad_cidr") from exc
    if net.prefixlen < 16:
        raise err(400, "err.cidr_too_big")
    if body.mode not in ("auto", "arp", "ping"):
        raise err(400, "err.bad_mode")
    return str(net)


@router.get("/subnets")
def list_subnets(s: Session = Depends(get_session)):
    return s.exec(select(Subnet)).all()


@router.post("/subnets")
def add_subnet(body: SubnetBody, s: Session = Depends(get_session)):
    cidr = _validate_subnet(body)
    if s.exec(select(Subnet).where(Subnet.cidr == cidr)).first():
        raise err(409, "err.subnet_exists")
    sn = Subnet(cidr=cidr, label=body.label.strip() or cidr, enabled=body.enabled, mode=body.mode)
    s.add(sn)
    s.commit()
    return sn


@router.put("/subnets/{subnet_id}")
def update_subnet(subnet_id: int, body: SubnetBody, s: Session = Depends(get_session)):
    sn = s.get(Subnet, subnet_id)
    if not sn:
        raise err(404, "err.subnet_not_found")
    sn.cidr, sn.label, sn.enabled, sn.mode = _validate_subnet(body), body.label.strip() or sn.cidr, body.enabled, body.mode
    s.add(sn)
    s.commit()
    return sn


@router.delete("/subnets/{subnet_id}")
def delete_subnet(subnet_id: int, s: Session = Depends(get_session)):
    sn = s.get(Subnet, subnet_id)
    if not sn:
        raise err(404, "err.subnet_not_found")
    for d in s.exec(select(Device).where(Device.subnet_id == subnet_id)):
        d.subnet_id = None
        s.add(d)
    s.delete(sn)
    s.commit()
    return {"ok": True}


# ------------------------------------------------------------------ router & izleyici
@router.get("/router")
def router_audit():
    return json.loads(settings_store.get_raw("router_audit", "{}") or "{}")


@router.get("/watchdog")
def watchdog_status():
    return {
        "running": watchdog_service.running,
        "gateway_mac": settings_store.get_raw("gateway_mac") or None,
        "dhcp_server_known": settings_store.get_raw("dhcp_server_known") or None,
        "last_dhcp_probe": json.loads(settings_store.get_raw("dhcp_probe", "{}") or "{}"),
    }


@router.post("/watchdog/dhcp-probe")
def run_dhcp_probe():
    return watchdog_service.probe_dhcp()


class GatewayBody(BaseModel):
    mac: str


@router.post("/watchdog/accept-gateway")
def accept_gateway(body: GatewayBody):
    from app.netutil import normalize_mac

    mac = normalize_mac(body.mac)
    if not mac:
        raise err(400, "err.bad_mac")
    watchdog_service.accept_gateway_mac(mac)
    return {"ok": True, "gateway_mac": mac}


class DhcpServerBody(BaseModel):
    server: str


@router.post("/watchdog/accept-dhcp")
def accept_dhcp(body: DhcpServerBody):
    try:
        ipaddress.IPv4Address(body.server)
    except ValueError as exc:
        raise err(400, "err.bad_ip") from exc
    settings_store.set_raw("dhcp_server_known", body.server)
    return {"ok": True}


# ------------------------------------------------------------------ rapor
@router.post("/report/send")
def send_report():
    from app.main import templates
    from app.report import send_weekly

    if not settings_store.apprise_url_list():
        raise err(400, "err.report_no_target")
    if not send_weekly(templates.env):
        raise err(502, "err.report_failed")
    return {"ok": True}


@router.get("/report/preview", response_class=HTMLResponse)
def preview_report():
    """E-postanın birebir önizlemesi: bildirimlerle aynı (varsayılan) dilde."""
    from app.main import templates
    from app.report import build, render

    with i18n.use_lang(i18n.default_language()):
        return render(templates.env, build())


# ------------------------------------------------------------------ gizli MAC eşleşme önerileri
@router.get("/suggestions")
def list_suggestions(s: Session = Depends(get_session)):
    return [suggestion_dict(sg, s) for sg in pending_suggestions(s)]


def _get_suggestion(s: Session, suggestion_id: int) -> MergeSuggestion:
    sg = s.get(MergeSuggestion, suggestion_id)
    if not sg or sg.status != "pending":
        raise err(404, "err.suggestion_not_found")
    return sg


@router.post("/suggestions/{suggestion_id}/accept")
def accept_suggestion(suggestion_id: int, s: Session = Depends(get_session)):
    """Yeni (gizli MAC) kayıt, önerilen bilinen cihaza birleştirilir."""
    from app.pipeline import EventSink

    sg = _get_suggestion(s, suggestion_id)
    try:
        dst = merge_devices(s, sg.device_id, sg.candidate_id, EventSink())
    except ValueError as exc:
        raise err(400, str(exc)) from exc
    s.commit()
    return device_dict(dst)


@router.post("/suggestions/{suggestion_id}/reject")
def reject_suggestion(suggestion_id: int, s: Session = Depends(get_session)):
    """Farklı cihazlar: öneri kapatılır ve bu çift bir daha önerilmez."""
    sg = _get_suggestion(s, suggestion_id)
    sg.status = "rejected"
    s.add(sg)
    s.commit()
    return {"ok": True}


@router.get("/snapshot")
def current_snapshot(s: Session = Depends(get_session)):
    return build_snapshot(s)
