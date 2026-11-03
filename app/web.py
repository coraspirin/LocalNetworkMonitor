"""HTML sayfaları (Jinja2)."""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from app import settings_store
from app.api import device_summaries, finding_dict, get_device, presence_buckets
from app.db import get_session
from app.models import Device, DeviceEvent, Scan, ScanDiff, SecurityScoreHistory, Subnet, iso, utcnow
from app.monitor import watchdog_service
from app.pipeline import compute_score, manager
from app.scanner import analysis

router = APIRouter(include_in_schema=False)


def _render(request: Request, name: str, ctx: dict) -> HTMLResponse:
    from app.main import templates

    return templates.TemplateResponse(request, name, ctx | {"nav": name.split(".")[0]})


def score_chart(points: list[tuple], width: int = 600, height: int = 120) -> dict:
    """[(ts, score)] -> SVG polyline koordinatları."""
    if not points:
        return {"points": "", "width": width, "height": height, "dots": []}
    if len(points) == 1:
        points = [points[0], points[0]]
    n = len(points)
    coords = []
    for i, (_, score) in enumerate(points):
        x = round(i * (width - 10) / (n - 1) + 5, 1)
        y = round(height - 5 - score * (height - 10) / 100, 1)
        coords.append((x, y))
    return {"points": " ".join(f"{x},{y}" for x, y in coords), "width": width, "height": height,
            "dots": [{"x": x, "y": y, "score": p[1], "ts": p[0]} for (x, y), p in zip(coords, points)][-1:]}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, s: Session = Depends(get_session)):
    devices = device_summaries(s, include_archived=True)
    active = [d for d in devices if not d["archived"]]
    score, counts = compute_score(s)
    subnets = s.exec(select(Subnet)).all()
    last_deep = s.exec(select(Scan).where(Scan.kind == "deep", Scan.status == "done").order_by(Scan.id.desc())).first()
    recent = s.exec(select(DeviceEvent).order_by(DeviceEvent.ts.desc()).limit(8)).all()
    names = {d["id"]: d["name"] for d in devices}
    return _render(request, "dashboard.html", {
        "devices": devices,
        "subnets": subnets,
        "subnet_names": {sn.id: sn.label for sn in subnets},
        "score": score,
        "grade": analysis.score_grade(score),
        "counts": counts,
        "active_count": len(active),
        "online": sum(1 for d in active if d["online"]),
        "new_today": sum(1 for d in active if d["first_seen"] >= iso(utcnow() - timedelta(days=1))),
        "pending_matches": sum(1 for d in active if d["pending_suggestions"]),
        "last_deep": last_deep,
        "recent": recent,
        "names": names,
        "running": manager.busy,
    })


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(device_id: int, request: Request, s: Session = Depends(get_session)):
    d = get_device(device_id, s)
    others = [x for x in device_summaries(s) if x["id"] != device_id]
    return _render(request, "device.html", {
        "d": d,
        "p24": presence_buckets(s, device_id, 24, 96),
        "p7": presence_buckets(s, device_id, 24 * 7, 168),
        "others": others,
        "subnet": s.get(Subnet, d["subnet_id"]) if d["subnet_id"] else None,
    })


@router.get("/security", response_class=HTMLResponse)
def security_page(request: Request, s: Session = Depends(get_session)):
    from app.api import list_findings

    score, counts = compute_score(s)
    hist = s.exec(select(SecurityScoreHistory).where(SecurityScoreHistory.ts >= utcnow() - timedelta(days=60)).order_by(SecurityScoreHistory.ts)).all()
    findings = list_findings(include_resolved=False, s=s)
    names = {d.id: d for d in s.exec(select(Device))}
    return _render(request, "security.html", {
        "score": score,
        "grade": analysis.score_grade(score),
        "counts": counts,
        "chart": score_chart([(h.ts, h.score) for h in hist]),
        "history_len": len(hist),
        "findings": findings,
        "devices": names,
        "router": json.loads(settings_store.get_raw("router_audit", "{}") or "{}"),
        "watchdog": {
            "running": watchdog_service.running,
            "gateway_mac": settings_store.get_raw("gateway_mac") or None,
            "dhcp_server_known": settings_store.get_raw("dhcp_server_known") or None,
            "last_dhcp_probe": json.loads(settings_store.get_raw("dhcp_probe", "{}") or "{}"),
        },
    })


@router.get("/history", response_class=HTMLResponse)
def history_page(request: Request, kind: str | None = None, s: Session = Depends(get_session)):
    q = select(DeviceEvent).order_by(DeviceEvent.ts.desc()).limit(300)
    if kind:
        q = q.where(DeviceEvent.kind == kind)
    events = s.exec(q).all()
    scans = s.exec(select(Scan).order_by(Scan.id.desc()).limit(50)).all()
    diffs = {d.scan_id: d.change_count for d in s.exec(select(ScanDiff))}
    names = {d.id: d.display_name for d in s.exec(select(Device))}
    kinds = sorted({k for (k,) in s.execute(select(DeviceEvent.kind).distinct())})
    return _render(request, "history.html", {"events": events, "scans": scans, "diffs": diffs, "names": names, "kind": kind, "kinds": kinds})


@router.get("/diff", response_class=HTMLResponse)
def diff_page(request: Request, a: int | None = None, b: int | None = None, s: Session = Depends(get_session)):
    from app.api import diff

    deep = s.exec(select(Scan).where(Scan.kind == "deep", Scan.status == "done").order_by(Scan.id.desc())).all()
    try:
        result = diff(a=a, b=b, s=s)
    except HTTPException:
        result = {"a": None, "b": None, "changes": []}
    return _render(request, "diff.html", {"scans": deep, "result": result})


@router.get("/map", response_class=HTMLResponse)
def map_page(request: Request):
    return _render(request, "map.html", {})


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, s: Session = Depends(get_session)):
    from app import scheduler

    return _render(request, "settings.html", {
        "cfg": settings_store.all_settings(),
        "subnets": s.exec(select(Subnet)).all(),
        "next_runs": scheduler.next_runs(),
        "gateway_mac": settings_store.get_raw("gateway_mac") or "",
        "dhcp_server_known": settings_store.get_raw("dhcp_server_known") or "",
    })


@router.get("/report", response_class=HTMLResponse)
def report_page(request: Request):
    from app import i18n

    names = {"tr": "Türkçe", "en": "English"}
    return _render(request, "report.html", {"has_targets": bool(settings_store.apprise_url_list()),
                                            "default_lang_name": names.get(i18n.default_language(), "Türkçe")})


__all__ = ["router", "finding_dict"]
