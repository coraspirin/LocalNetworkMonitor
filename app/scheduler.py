"""Zamanlanmış işler: hızlı keşif, derin tarama, DHCP yoklaması, haftalık rapor, temizlik."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import delete

from app import settings_store
from app.config import get_settings
from app.db import session_scope
from app.models import DeviceEvent, PresenceSample, utcnow
from app.pipeline import archive_stale, manager

log = logging.getLogger(__name__)

scheduler = BackgroundScheduler(timezone=get_settings().tz, job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 300})
_templates = None


def cleanup() -> None:
    days = settings_store.get("presence_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    with session_scope() as s:
        s.execute(delete(PresenceSample).where(PresenceSample.ts < cutoff))
        s.execute(delete(DeviceEvent).where(DeviceEvent.ts < utcnow() - timedelta(days=max(days, 90))))
        archived = archive_stale(s)
    if archived:
        log.info("%d eski gizli MAC kaydı arşivlendi", archived)
    log.info("%d günden eski varlık örnekleri silindi", days)


def _weekly_report() -> None:
    from app.report import send_weekly

    if settings_store.apprise_url_list():
        send_weekly(_templates)


def _dhcp_probe() -> None:
    from app.monitor import watchdog_service

    if settings_store.get("enable_watchdog"):
        watchdog_service.probe_dhcp()


def configure() -> None:
    cfg = settings_store.all_settings()
    scheduler.add_job(manager.run_quick, IntervalTrigger(minutes=max(1, cfg["quick_interval_min"])), id="quick", replace_existing=True)
    if cfg["deep_interval_hours"] > 0:
        scheduler.add_job(manager.run_deep, IntervalTrigger(hours=cfg["deep_interval_hours"]), id="deep", replace_existing=True)
    elif scheduler.get_job("deep"):
        scheduler.remove_job("deep")
    if cfg["dhcp_probe_interval_min"] > 0:
        scheduler.add_job(_dhcp_probe, IntervalTrigger(minutes=cfg["dhcp_probe_interval_min"]), id="dhcp", replace_existing=True)
    elif scheduler.get_job("dhcp"):
        scheduler.remove_job("dhcp")
    scheduler.add_job(
        _weekly_report, CronTrigger(day_of_week=cfg["report_weekday"], hour=cfg["report_hour"], minute=7),
        id="weekly_report", replace_existing=True,
    )
    scheduler.add_job(cleanup, IntervalTrigger(hours=24), id="cleanup", replace_existing=True)


def start(templates_env, run_initial: bool = True) -> None:
    global _templates
    _templates = templates_env
    configure()
    if run_initial:
        # açılıştan kısa süre sonra bir derin tarama (ilk kurulum) veya hızlı keşif
        from sqlmodel import select

        from app.models import Scan

        with session_scope() as s:
            has_deep = s.exec(select(Scan).where(Scan.kind == "deep", Scan.status == "done")).first() is not None
        first = manager.run_quick if has_deep else manager.run_deep
        scheduler.add_job(first, "date", run_date=datetime.now(ZoneInfo(get_settings().tz)) + timedelta(seconds=5), id="initial", replace_existing=True)
    scheduler.start()


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)


def next_runs() -> dict[str, str | None]:
    out = {}
    for job in scheduler.get_jobs():
        out[job.id] = job.next_run_time.isoformat() if job.next_run_time else None
    return out
