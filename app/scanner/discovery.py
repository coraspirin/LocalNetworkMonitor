"""Hızlı keşif: ARP taraması (doğrudan bağlı ağlar) veya nmap ping taraması (yönlendirilmiş ağlar)."""

from __future__ import annotations

import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

from app.netutil import iface_for, normalize_mac
from app.scanner import nmapxml

log = logging.getLogger(__name__)


@dataclass
class SeenHost:
    ip: str
    mac: str | None
    rtt_ms: float | None = None
    hostname: str | None = None
    nmap_vendor: str | None = None


def arp_sweep(cidr: str, iface: str | None = None, timeout: float = 2.0, rounds: int = 2) -> list[SeenHost]:
    from scapy.all import ARP, Ether, conf, srp  # ağır import, tembel yükle

    conf.verb = 0
    found: dict[str, SeenHost] = {}
    for _ in range(rounds):
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=timeout,
            iface=iface,
            retry=0,
            verbose=False,
        )
        for sent, recv in answered:
            ip = recv.psrc
            rtt = max(0.0, (recv.time - sent.sent_time) * 1000.0) if getattr(sent, "sent_time", None) else None
            if ip not in found:
                found[ip] = SeenHost(ip=ip, mac=normalize_mac(recv.hwsrc), rtt_ms=round(rtt, 2) if rtt else None)
    return list(found.values())


def nmap_ping_sweep(cidr: str) -> list[SeenHost]:
    cmd = ["nmap", "-sn", "-n", "-PE", "-PS22,80,443,445,3389", "-PA80", "--max-retries", "1", "-oX", "-", cidr]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("nmap ping taraması başarısız: %s", exc)
        return []
    return [
        SeenHost(ip=h.ip, mac=h.mac, rtt_ms=h.rtt_ms, nmap_vendor=h.vendor)
        for h in nmapxml.parse(out)
        if h.status == "up"
    ]


def sweep(cidr: str, mode: str = "auto") -> tuple[list[SeenHost], str]:
    """Bir ağı tarar; (hostlar, kullanılan yöntem) döndürür."""
    iface = iface_for(cidr)
    use_arp = mode == "arp" or (mode == "auto" and iface is not None)
    if use_arp:
        try:
            hosts = arp_sweep(cidr, iface=iface)
            return hosts, "arp"
        except Exception as exc:  # izin yoksa vb.
            log.warning("ARP taraması başarısız (%s), ping taramasına geçiliyor", exc)
    return nmap_ping_sweep(cidr), "ping"


def reverse_dns(ips: list[str], total_timeout: float = 4.0) -> dict[str, str]:
    result: dict[str, str] = {}

    def _lookup(ip: str):
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and name != ip:
                result[ip] = name.rstrip(".")
        except OSError:
            pass

    if not ips:
        return result
    pool = ThreadPoolExecutor(max_workers=16)
    futures = [pool.submit(_lookup, ip) for ip in ips]
    wait(futures, timeout=total_timeout)
    pool.shutdown(wait=False, cancel_futures=True)
    return dict(result)
