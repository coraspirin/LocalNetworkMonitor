"""Derin tarama: nmap ile port, servis sürümü, işletim sistemi ve NSE güvenlik scriptleri."""

from __future__ import annotations

import logging
import os
import subprocess
from functools import lru_cache
from pathlib import Path

from app.scanner import nmapxml

log = logging.getLogger(__name__)

BASE_SCRIPTS = [
    "ftp-anon",
    "telnet-encryption",
    "smb-protocols",
    "ssl-cert",
    "http-title",
    "http-default-accounts",
    "nbstat",
]


SCRIPT_DIRS = [Path("/usr/share/nmap/scripts"), Path("/usr/local/share/nmap/scripts")]


@lru_cache(maxsize=1)
def available_scripts() -> set[str] | None:
    """Kurulu NSE scriptleri; dizin bulunamazsa None (filtreleme yapılmaz)."""
    for d in SCRIPT_DIRS:
        if d.is_dir():
            return {p.stem for p in d.glob("*.nse")}
    return None


def build_command(ip: str, top_ports: int = 1000, host_timeout_min: int = 10, vulners: bool = True) -> list[str]:
    scripts = list(BASE_SCRIPTS)
    if vulners:
        scripts.append("vulners")
    installed = available_scripts()
    if installed is not None:
        missing = [x for x in scripts if x not in installed]
        if missing:
            log.debug("Kurulu olmayan NSE scriptleri atlandı: %s", ", ".join(missing))
        scripts = [x for x in scripts if x in installed]
    cmd = [
        "nmap",
        "-sV",
        "--version-light",
        "-T4",
        "--top-ports",
        str(top_ports),
        "--host-timeout",
        f"{host_timeout_min}m",
        "-oX",
        "-",
    ]
    if scripts:
        cmd[-2:-2] = ["--script", ",".join(scripts), "--script-args", "vulners.mincvss=5.0"]
    if os.geteuid() == 0:
        # OS tespiti ve SYN taraması root (NET_RAW) gerektirir
        cmd[1:1] = ["-sS", "-O", "--osscan-guess"]
    else:
        cmd[1:1] = ["-sT"]
    cmd.append(ip)
    return cmd


def scan_host(ip: str, top_ports: int = 1000, host_timeout_min: int = 10, vulners: bool = True) -> nmapxml.HostResult | None:
    cmd = build_command(ip, top_ports, host_timeout_min, vulners)
    log.info("nmap: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=host_timeout_min * 60 + 120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("nmap %s için başarısız: %s", ip, exc)
        return None
    if proc.returncode != 0 and not proc.stdout:
        log.warning("nmap hata (%s): %s", ip, proc.stderr.strip()[:500])
        return None
    try:
        hosts = nmapxml.parse(proc.stdout)
    except Exception as exc:  # bozuk XML
        log.warning("nmap XML ayrıştırılamadı (%s): %s", ip, exc)
        return None
    return hosts[0] if hosts else None
