"""Haftalık özet raporu."""

from __future__ import annotations

from datetime import timedelta

from sqlmodel import select

from app import i18n, notify
from app.db import session_scope
from app.models import Device, DeviceEvent, Finding, SecurityScoreHistory, utcnow
from app.pipeline import compute_score
from app.scanner.analysis import score_grade, severity_rank


def build(days: int = 7) -> dict:
    since = utcnow() - timedelta(days=days)
    with session_scope() as s:
        devices = s.exec(select(Device)).all()
        by_id = {d.id: d for d in devices}
        events = s.exec(select(DeviceEvent).where(DeviceEvent.ts >= since).order_by(DeviceEvent.ts.desc())).all()
        new_devices = [d for d in devices if d.first_seen >= since]
        left = [e for e in events if e.kind == "left"]
        new_findings = s.exec(select(Finding).where(Finding.first_seen >= since, Finding.ignored == False)).all()  # noqa: E712
        open_findings = s.exec(select(Finding).where(Finding.resolved == False, Finding.ignored == False)).all()  # noqa: E712
        score, counts = compute_score(s)
        old = s.exec(select(SecurityScoreHistory).where(SecurityScoreHistory.ts <= since).order_by(SecurityScoreHistory.ts.desc())).first()
        security_events = [e for e in events if e.kind in ("arp_spoof", "rogue_dhcp")]
        return {
            "days": days,
            "generated": utcnow(),
            "total": len(devices),
            "online": sum(1 for d in devices if d.online),
            "new_devices": new_devices,
            "left": [(e, by_id.get(e.device_id)) for e in left],
            "new_findings": sorted(new_findings, key=lambda f: -severity_rank(f.severity)),
            "open_findings": sorted(open_findings, key=lambda f: -severity_rank(f.severity))[:20],
            "score": score,
            "grade": score_grade(score),
            "score_prev": old.score if old else None,
            "counts": counts,
            "security_events": security_events,
            "devices": by_id,
        }


def render(env, data: dict) -> str:
    return env.get_template("report_email.html").render(r=data)


def send_weekly(env) -> bool:
    with i18n.use_lang(i18n.default_language()):
        data = build()
        html = render(env, data)
        subject = i18n.t("mail.subject", score=data["score"])
    return notify.send(subject, html, "info", html=True, background=False)
