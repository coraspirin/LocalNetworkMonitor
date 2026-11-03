"""Veritabanı modelleri (SQLModel / SQLite)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """UTC ISO-8601 (``...Z``) gösterimi."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


SEVERITIES = ["info", "low", "medium", "high", "critical"]


class Subnet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cidr: str = Field(index=True, unique=True)
    label: str = "Ana ağ"
    enabled: bool = True
    # auto: doğrudan bağlıysa ARP, değilse ping; arp; ping
    mode: str = "auto"


class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    mac: Optional[str] = Field(default=None, index=True)
    ip: Optional[str] = Field(default=None, index=True)
    subnet_id: Optional[int] = Field(default=None, foreign_key="subnet.id")

    name: Optional[str] = None  # kullanıcının verdiği isim
    location: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    trusted: bool = False

    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    device_type: str = "unknown"
    is_random_mac: bool = False
    is_gateway: bool = False

    mdns_name: Optional[str] = None
    mdns_services: str = "[]"  # JSON
    ssdp_info: str = "{}"  # JSON
    netbios_name: Optional[str] = None

    online: bool = True
    missed_scans: int = 0
    last_rtt_ms: Optional[float] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    last_deep_scan: Optional[datetime] = None

    @property
    def display_name(self) -> str:
        return (
            self.name
            or self.mdns_name
            or self.hostname
            or self.netbios_name
            or self.ssdp().get("friendlyName")
            or self.vendor
            or self.ip
            or self.mac
            or f"Cihaz #{self.id}"
        )

    @property
    def key(self) -> str:
        return self.mac or f"ip-{self.ip}"

    def mdns(self) -> list[dict]:
        try:
            return json.loads(self.mdns_services or "[]")
        except ValueError:
            return []

    def ssdp(self) -> dict:
        try:
            return json.loads(self.ssdp_info or "{}")
        except ValueError:
            return {}


class DeviceAlias(SQLModel, table=True):
    """Bir cihaza ait tüm MAC adresleri (rastgele MAC birleştirme için)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    mac: str = Field(index=True, unique=True)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class Port(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None
    tls: bool = False

    @property
    def label(self) -> str:
        return " ".join(x for x in [self.service, self.product, self.version] if x)


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)
    device_id: Optional[int] = Field(default=None, foreign_key="device.id", index=True)
    severity: str = "info"
    title: str
    description: str = ""
    remediation: str = ""
    source: str = "rule"  # rule, nse, router, watchdog
    cves: str = "[]"  # JSON
    port: Optional[int] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    resolved: bool = False
    ignored: bool = False

    def cve_list(self) -> list[dict]:
        try:
            return json.loads(self.cves or "[]")
        except ValueError:
            return []


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = "quick"  # quick, deep
    trigger: str = "schedule"  # schedule, manual
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    status: str = "running"  # running, done, failed
    hosts_found: int = 0
    error: Optional[str] = None
    snapshot: str = "{}"  # JSON; derin taramalarda diff için


class ScanDiff(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    prev_scan_id: Optional[int] = Field(default=None, foreign_key="scan.id")
    changes: str = "[]"  # JSON
    change_count: int = 0
    created_at: datetime = Field(default_factory=utcnow)


class DeviceEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: Optional[int] = Field(default=None, foreign_key="device.id", index=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    kind: str  # joined, left, returned, ip_changed, port_opened, port_closed, finding, arp_spoof, rogue_dhcp, merged
    severity: str = "info"
    message: str = ""


class PresenceSample(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    online: bool = True
    rtt_ms: Optional[float] = None


class SecurityScoreHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    score: int
    finding_counts: str = "{}"  # JSON


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str = ""
