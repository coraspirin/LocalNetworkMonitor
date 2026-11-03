"""Çalışma zamanında değiştirilebilen ayarlar (env varsayılanları + DB üzerine yazma)."""

from __future__ import annotations

from typing import Any

from sqlmodel import Session, select

from app.config import get_settings
from app.db import session_scope
from app.models import Setting, Subnet
from app.netutil import connected_subnets

# anahtar -> tip
EDITABLE: dict[str, type] = {
    "quick_interval_min": int,
    "deep_interval_hours": int,
    "top_ports": int,
    "scan_concurrency": int,
    "host_timeout_min": int,
    "enable_vulners": bool,
    "enable_watchdog": bool,
    "dhcp_probe_interval_min": int,
    "notify_on_leave": bool,
    "presence_retention_days": int,
    "apprise_urls": str,
    "report_weekday": str,
    "report_hour": int,
    "default_language": str,
    "random_mac_notify": str,
}

CHOICES: dict[str, tuple[str, ...]] = {
    "default_language": ("tr", "en"),
    "random_mac_notify": ("smart", "always", "never"),
    "report_weekday": ("mon", "tue", "wed", "thu", "fri", "sat", "sun"),
}


def _coerce(value: Any, typ: type) -> Any:
    if typ is bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on", "evet"}
    if typ is int:
        return int(value)
    return str(value)


def get(key: str, session: Session | None = None) -> Any:
    typ = EDITABLE[key]
    default = getattr(get_settings(), key)

    def _read(s: Session):
        row = s.get(Setting, key)
        value = _coerce(row.value, typ) if row is not None else default
        if key in CHOICES and value not in CHOICES[key]:
            return CHOICES[key][0]
        return value

    if session is not None:
        return _read(session)
    with session_scope() as s:
        return _read(s)


def all_settings() -> dict[str, Any]:
    with session_scope() as s:
        return {k: get(k, s) for k in EDITABLE}


def update(values: dict[str, Any]) -> dict[str, Any]:
    with session_scope() as s:
        for key, raw in values.items():
            if key not in EDITABLE:
                continue
            try:
                value = _coerce(raw, EDITABLE[key])
            except (TypeError, ValueError):
                raise ValueError(key) from None
            if EDITABLE[key] is int and value < 0:
                raise ValueError(key)
            if key in CHOICES and value not in CHOICES[key]:
                raise ValueError(key)
            row = s.get(Setting, key) or Setting(key=key)
            row.value = str(value)
            s.add(row)
    return all_settings()


def get_raw(key: str, default: str = "") -> str:
    with session_scope() as s:
        row = s.get(Setting, key)
        return row.value if row else default


def set_raw(key: str, value: str) -> None:
    with session_scope() as s:
        row = s.get(Setting, key) or Setting(key=key)
        row.value = value
        s.add(row)


def apprise_url_list(raw: str | None = None) -> list[str]:
    raw = get("apprise_urls") if raw is None else raw
    return [u.strip() for u in raw.replace(",", "\n").splitlines() if u.strip()]


def ensure_subnets() -> None:
    """İlk açılışta ağ listesini env'den veya otomatik tespitle doldurur."""
    with session_scope() as s:
        if s.exec(select(Subnet)).first() is not None:
            return
        env = get_settings().subnets
        cidrs = [c.strip() for c in env.split(",") if c.strip()] if env else [c for c, _ in connected_subnets()]
        for i, cidr in enumerate(cidrs):
            s.add(Subnet(cidr=cidr, label="Ana ağ" if i == 0 else f"Ağ {i + 1}"))
