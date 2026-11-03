"""Cihazların kendini tanıttığı protokoller: mDNS (Bonjour), SSDP/UPnP."""

from __future__ import annotations

import logging
import socket
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

SSDP_ADDR = ("239.255.255.250", 1900)


# --------------------------------------------------------------------- mDNS
def mdns_browse(timeout: float = 5.0) -> dict[str, dict]:
    """IP -> {"name": hostname, "services": [{type, name, port, txt}]}"""
    try:
        from zeroconf import ServiceBrowser, Zeroconf, ZeroconfServiceTypes
    except ImportError:  # pragma: no cover
        return {}

    result: dict[str, dict] = defaultdict(lambda: {"name": None, "services": []})
    zc = None
    try:
        zc = Zeroconf()
        types = ZeroconfServiceTypes.find(zc=zc, timeout=min(3.0, timeout))
        found: list[tuple[str, str]] = []

        class _Listener:
            def add_service(self, zc_, type_, name):
                found.append((type_, name))

            def update_service(self, *a):
                pass

            def remove_service(self, *a):
                pass

        browsers = [ServiceBrowser(zc, t, _Listener()) for t in types]
        time.sleep(max(1.0, timeout - 3.0))
        for b in browsers:
            b.cancel()

        for type_, name in found[:300]:
            info = zc.get_service_info(type_, name, timeout=800)
            if not info:
                continue
            txt = {}
            for k, v in (info.properties or {}).items():
                try:
                    key = k.decode() if isinstance(k, bytes) else str(k)
                    val = v.decode(errors="ignore") if isinstance(v, bytes) else ("" if v is None else str(v))
                except Exception:
                    continue
                if key in ("md", "model", "fn", "ty", "manufacturer", "am", "product", "usb_MDL", "vendor", "rpMd"):
                    txt[key] = val[:80]
            for ip in info.parsed_addresses():
                if ":" in ip:
                    continue
                entry = result[ip]
                if info.server and not entry["name"]:
                    entry["name"] = info.server.rstrip(".").removesuffix(".local")
                svc = {
                    "type": type_.removesuffix(".local.").rstrip("."),
                    "name": name.removesuffix("." + type_).strip(),
                    "port": info.port,
                    "txt": txt,
                }
                if svc not in entry["services"]:
                    entry["services"].append(svc)
    except Exception as exc:
        log.warning("mDNS taraması başarısız: %s", exc)
    finally:
        if zc is not None:
            zc.close()
    return dict(result)


# --------------------------------------------------------------------- SSDP
@dataclass
class SsdpResponse:
    ip: str
    location: str | None = None
    server: str | None = None
    st: str | None = None
    usn: str | None = None


@dataclass
class SsdpDevice:
    ip: str
    locations: list[str] = field(default_factory=list)
    server: str | None = None
    sts: list[str] = field(default_factory=list)
    description: dict = field(default_factory=dict)

    @property
    def is_igd(self) -> bool:
        haystack = " ".join(self.sts) + " " + str(self.description.get("deviceType", ""))
        return "InternetGatewayDevice" in haystack or "WANIPConnection" in haystack


def parse_ssdp_response(data: bytes, ip: str) -> SsdpResponse:
    text = data.decode(errors="ignore")
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return SsdpResponse(
        ip=ip,
        location=headers.get("location"),
        server=headers.get("server"),
        st=headers.get("st") or headers.get("nt"),
        usn=headers.get("usn"),
    )


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse_device_description(xml_text: str) -> dict:
    root = _strip_ns(ET.fromstring(xml_text))
    dev = root.find("device")
    if dev is None:
        return {}
    out = {}
    for key in ("deviceType", "friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "serialNumber", "presentationURL"):
        el = dev.find(key)
        if el is not None and el.text:
            out[key] = el.text.strip()[:120]
    base = root.find("URLBase")
    if base is not None and base.text:
        out["URLBase"] = base.text.strip()
    return out


def ssdp_search(timeout: float = 3.0, st: str = "ssdp:all") -> list[SsdpResponse]:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {st}\r\n\r\n"
    ).encode()
    responses: list[SsdpResponse] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        for _ in range(2):
            sock.sendto(msg, SSDP_ADDR)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, (ip, _) = sock.recvfrom(65507)
            except socket.timeout:
                continue
            responses.append(parse_ssdp_response(data, ip))
    except OSError as exc:
        log.warning("SSDP araması başarısız: %s", exc)
    finally:
        sock.close()
    return responses


def ssdp_discover(timeout: float = 3.0) -> dict[str, SsdpDevice]:
    devices: dict[str, SsdpDevice] = {}
    for r in ssdp_search(timeout):
        d = devices.setdefault(r.ip, SsdpDevice(ip=r.ip))
        if r.location and r.location not in d.locations:
            d.locations.append(r.location)
        if r.st and r.st not in d.sts:
            d.sts.append(r.st)
        d.server = d.server or r.server
    with httpx.Client(timeout=2.0) as client:
        for d in devices.values():
            for loc in d.locations[:4]:
                if urlparse(loc).hostname != d.ip:
                    continue  # başka hosta yönlendiren LOCATION'ları takip etme
                try:
                    resp = client.get(loc)
                    desc = parse_device_description(resp.text)
                except Exception:
                    continue
                if desc:
                    # IGD açıklamasını tercih et, yoksa ilk başarılı olanı al
                    if not d.description or "InternetGatewayDevice" in desc.get("deviceType", ""):
                        d.description = desc | {"location": loc}
                    if "InternetGatewayDevice" in desc.get("deviceType", ""):
                        break
    return devices
