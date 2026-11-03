"""Ağ yardımcıları: bağlı ağların, varsayılan ağ geçidinin tespiti ve MAC işlemleri."""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

ROUTE_FILE = Path("/proc/net/route")
IGNORED_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "zt", "cni", "flannel")


@dataclass
class Route:
    iface: str
    destination: str
    gateway: str
    mask: str
    is_gateway_route: bool


def _hex_to_ip(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(value, 16)))


def read_routes(route_file: Path = ROUTE_FILE) -> list[Route]:
    routes: list[Route] = []
    try:
        lines = route_file.read_text().splitlines()[1:]
    except OSError:
        return routes
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gw, flags, mask = parts[0], parts[1], parts[2], int(parts[3], 16), parts[7]
        routes.append(
            Route(
                iface=iface,
                destination=_hex_to_ip(dest),
                gateway=_hex_to_ip(gw),
                mask=_hex_to_ip(mask),
                is_gateway_route=bool(flags & 0x2),
            )
        )
    return routes


def default_gateway(route_file: Path = ROUTE_FILE) -> tuple[str, str] | None:
    """(gateway_ip, iface) döndürür."""
    for r in read_routes(route_file):
        if r.destination == "0.0.0.0" and r.is_gateway_route:
            return r.gateway, r.iface
    return None


def connected_subnets(route_file: Path = ROUTE_FILE) -> list[tuple[str, str]]:
    """Doğrudan bağlı (L2) ağları (cidr, iface) olarak döndürür."""
    result: list[tuple[str, str]] = []
    for r in read_routes(route_file):
        if r.is_gateway_route or r.destination == "0.0.0.0":
            continue
        if r.iface.startswith(IGNORED_IFACE_PREFIXES):
            continue
        net = ipaddress.IPv4Network(f"{r.destination}/{r.mask}", strict=False)
        if net.is_loopback or net.is_link_local or net.prefixlen < 16:
            continue
        cidr = str(net)
        if cidr not in [c for c, _ in result]:
            result.append((cidr, r.iface))
    return result


def iface_for(cidr: str, route_file: Path = ROUTE_FILE) -> str | None:
    """CIDR doğrudan bağlıysa arayüz adını döndürür, değilse None (yönlendirilmiş ağ)."""
    target = ipaddress.IPv4Network(cidr, strict=False)
    for c, iface in connected_subnets(route_file):
        if ipaddress.IPv4Network(c).overlaps(target):
            return iface
    return None


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":").replace(".", "")
    if ":" not in cleaned and len(cleaned) == 12:
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    parts = cleaned.split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None


def is_random_mac(mac: str | None) -> bool:
    """Locally-administered biti set edilmiş MAC'ler (iOS/Android gizli MAC)."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    first = int(mac.split(":")[0], 16)
    return bool(first & 0x02) and not bool(first & 0x01)


def ip_sort_key(ip: str | None) -> tuple:
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except (ValueError, TypeError):
        return (1, 0)


def ip_in(ip: str | None, cidr: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False)
    except (ValueError, TypeError):
        return False
