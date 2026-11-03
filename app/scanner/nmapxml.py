"""nmap XML çıktısını ayrıştırma."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.netutil import normalize_mac


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra: str | None = None
    tunnel: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)
    script_tables: dict[str, list[dict]] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    status: str = "up"
    rtt_ms: float | None = None
    os_guess: str | None = None
    os_accuracy: int | None = None
    os_class: dict[str, str] = field(default_factory=dict)
    ports: list[PortResult] = field(default_factory=list)
    host_scripts: dict[str, str] = field(default_factory=dict)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]


def _elem_tables(elem: ET.Element) -> list[dict]:
    """vulners gibi scriptlerin <table> yapılarını düz sözlük listesine çevirir."""
    rows: list[dict] = []
    for table in elem.iter("table"):
        row = {e.get("key"): (e.text or "") for e in table.findall("elem") if e.get("key")}
        if row:
            rows.append(row)
    return rows


def parse(xml_text: str) -> list[HostResult]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    hosts: list[HostResult] = []
    for h in root.findall("host"):
        status = h.find("status")
        ip = mac = vendor = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = normalize_mac(addr.get("addr"))
                vendor = addr.get("vendor")
        if not ip:
            continue
        hr = HostResult(ip=ip, mac=mac, vendor=vendor, status=status.get("state") if status is not None else "up")

        hn = h.find("hostnames/hostname")
        if hn is not None:
            hr.hostname = hn.get("name")

        times = h.find("times")
        if times is not None and times.get("srtt"):
            try:
                hr.rtt_ms = round(int(times.get("srtt")) / 1000.0, 2)
            except ValueError:
                pass

        osmatches = h.findall("os/osmatch")
        if osmatches:
            best = max(osmatches, key=lambda m: int(m.get("accuracy", "0")))
            hr.os_guess = best.get("name")
            hr.os_accuracy = int(best.get("accuracy", "0"))
            oc = best.find("osclass")
            if oc is not None:
                hr.os_class = {k: v for k, v in oc.attrib.items() if k in ("type", "vendor", "osfamily", "osgen")}

        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            pr = PortResult(
                port=int(p.get("portid")),
                protocol=p.get("protocol", "tcp"),
                state=state.get("state") if state is not None else "unknown",
            )
            if svc is not None:
                pr.service = svc.get("name")
                pr.product = svc.get("product")
                pr.version = svc.get("version")
                pr.extra = svc.get("extrainfo")
                pr.tunnel = svc.get("tunnel")
                if not hr.os_guess and svc.get("ostype"):
                    hr.os_guess = svc.get("ostype")
            for sc in p.findall("script"):
                pr.scripts[sc.get("id")] = sc.get("output", "")
                tables = _elem_tables(sc)
                if tables:
                    pr.script_tables[sc.get("id")] = tables
            hr.ports.append(pr)

        for sc in h.findall("hostscript/script"):
            hr.host_scripts[sc.get("id")] = sc.get("output", "")

        hosts.append(hr)
    return hosts


_NBSTAT_RE = re.compile(r"NetBIOS name:\s*([^,\s]+)", re.I)


def netbios_name(host: HostResult) -> str | None:
    out = host.host_scripts.get("nbstat") or ""
    m = _NBSTAT_RE.search(out)
    if m and m.group(1) not in ("<unknown>",):
        return m.group(1)
    return None
