"""Router / UPnP IGD denetimi: dışarıya açılmış port yönlendirmelerini listeler."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.scanner.security import FindingData
from app.scanner.services import _strip_ns, ssdp_discover

log = logging.getLogger(__name__)

WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
DANGEROUS_INTERNAL_PORTS = {21, 22, 23, 445, 139, 3389, 5900, 2375, 3306, 5432, 6379, 27017, 1883, 554, 8080, 80}


@dataclass
class PortMapping:
    remote_host: str
    external_port: int
    protocol: str
    internal_port: int
    internal_client: str
    enabled: bool
    description: str
    lease: int = 0


@dataclass
class RouterAudit:
    igd_found: bool = False
    igd_ip: str | None = None
    location: str | None = None
    model: str | None = None
    external_ip: str | None = None
    service_type: str | None = None
    mappings: list[PortMapping] = field(default_factory=list)
    error: str | None = None


def find_wan_service(desc_xml: str, location: str) -> tuple[str, str] | None:
    """(service_type, absolute_control_url) döndürür."""
    root = _strip_ns(ET.fromstring(desc_xml))
    base_el = root.find("URLBase")
    base = base_el.text.strip() if base_el is not None and base_el.text else location
    for svc in root.iter("service"):
        st = (svc.findtext("serviceType") or "").strip()
        if any(w in st for w in WAN_SERVICES):
            ctrl = (svc.findtext("controlURL") or "").strip()
            if ctrl:
                return st, urljoin(base, ctrl)
    return None


def soap_body(service_type: str, action: str, args: dict[str, str | int]) -> str:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{inner}</u:{action}></s:Body></s:Envelope>'
    )


def parse_soap_response(xml_text: str) -> dict[str, str] | None:
    """Yanıt alanlarını döndürür; SOAP Fault ise None."""
    root = _strip_ns(ET.fromstring(xml_text))
    body = root.find("Body")
    if body is None or body.find("Fault") is not None or len(body) == 0:
        return None
    resp = body[0]
    return {child.tag: (child.text or "").strip() for child in resp}


def mapping_from_fields(f: dict[str, str]) -> PortMapping:
    def _int(v: str | None) -> int:
        try:
            return int(v or 0)
        except ValueError:
            return 0

    return PortMapping(
        remote_host=f.get("NewRemoteHost", ""),
        external_port=_int(f.get("NewExternalPort")),
        protocol=f.get("NewProtocol", ""),
        internal_port=_int(f.get("NewInternalPort")),
        internal_client=f.get("NewInternalClient", ""),
        enabled=f.get("NewEnabled", "1") in ("1", "true"),
        description=f.get("NewPortMappingDescription", ""),
        lease=_int(f.get("NewLeaseDuration")),
    )


def _soap(client: httpx.Client, url: str, service_type: str, action: str, args: dict) -> dict | None:
    resp = client.post(
        url,
        content=soap_body(service_type, action, args),
        headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service_type}#{action}"'},
    )
    try:
        return parse_soap_response(resp.text)
    except ET.ParseError:
        return None


def audit(ssdp_devices: dict | None = None, max_entries: int = 256) -> RouterAudit:
    result = RouterAudit()
    devices = ssdp_devices if ssdp_devices is not None else ssdp_discover()
    igd = next((d for d in devices.values() if d.is_igd), None)
    if igd is None:
        return result
    result.igd_found = True
    result.igd_ip = igd.ip
    result.model = " ".join(x for x in [igd.description.get("manufacturer"), igd.description.get("modelName")] if x) or None
    location = igd.description.get("location") or (igd.locations[0] if igd.locations else None)
    result.location = location
    if not location:
        return result
    try:
        with httpx.Client(timeout=3.0) as client:
            svc = find_wan_service(client.get(location).text, location)
            if not svc:
                return result
            st, ctrl = svc
            result.service_type = st
            ext = _soap(client, ctrl, st, "GetExternalIPAddress", {})
            if ext:
                result.external_ip = ext.get("NewExternalIPAddress")
            for i in range(max_entries):
                fields = _soap(client, ctrl, st, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
                if not fields:
                    break
                result.mappings.append(mapping_from_fields(fields))
    except Exception as exc:
        log.warning("UPnP denetimi başarısız: %s", exc)
        result.error = str(exc)
    return result


def audit_findings(a: RouterAudit) -> list[tuple[FindingData, str | None]]:
    """(bulgu, ilgili iç IP) listesi."""
    out: list[tuple[FindingData, str | None]] = []
    if not a.igd_found:
        return out
    out.append((
        FindingData("upnp-enabled", "medium", "upnp-enabled", {"model": a.model or ""}, None, "router"),
        a.igd_ip,
    ))
    for m in a.mappings:
        if not m.enabled:
            continue
        risky = m.internal_port in DANGEROUS_INTERNAL_PORTS
        out.append((
            FindingData("wan-forward", "high" if risky else "medium", "wan-forward",
                        {"proto": m.protocol, "ext": m.external_port, "client": m.internal_client, "iport": m.internal_port,
                         "desc": m.description, "ext_ip": a.external_ip or ""},
                        m.internal_port, "router", ident=f"{m.protocol.lower()}-{m.external_port}"),
            m.internal_client or None,
        ))
    return out
