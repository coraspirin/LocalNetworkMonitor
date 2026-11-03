"""Saf analiz fonksiyonları: rastgele MAC eşleştirme, tarama farkı (diff), güvenlik skoru."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.models import SEVERITIES

# ------------------------------------------------------------ MAC birleştirme


@dataclass
class Identity:
    """Bir cihazı MAC'ten bağımsız tanımlayan ipuçları."""

    device_id: int | None
    hostname: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None
    port_signature: frozenset[int] = frozenset()
    is_random_mac: bool = False


def _norm_name(name: str | None) -> str | None:
    if not name:
        return None
    n = name.strip().lower().rstrip(".")
    for suffix in (".local", ".lan", ".home", ".fritz.box", ".localdomain", ".home.arpa"):
        n = n.removesuffix(suffix)
    # DHCP'nin eklediği "-2" gibi çakışma eklerini görmezden gelme; yalnızca jenerik isimleri ele
    if n in {"", "android", "localhost", "unknown", "iphone", "ipad", "espressif", "esp"}:
        return None
    return n


def find_identity_match(candidate: Identity, existing: Iterable[Identity]) -> int | None:
    """Rastgele MAC'li yeni bir cihaz için aynı fiziksel cihazı bulmaya çalışır.

    Eşleşme sırası: mDNS adı > hostname > NetBIOS adı > (her ikisi de rastgele MAC ise) port imzası.
    Birden fazla aday varsa belirsizlik nedeniyle eşleştirme yapılmaz.
    """
    if not candidate.is_random_mac:
        return None
    cand_names = {
        "mdns": _norm_name(candidate.mdns_name),
        "host": _norm_name(candidate.hostname),
        "netbios": _norm_name(candidate.netbios_name),
    }
    others = [e for e in existing if e.device_id is not None and e.device_id != candidate.device_id]
    for attr in ("mdns", "host", "netbios"):
        value = cand_names[attr]
        if not value:
            continue
        matches = {
            e.device_id
            for e in others
            if value in {_norm_name(e.mdns_name), _norm_name(e.hostname), _norm_name(e.netbios_name)} - {None}
        }
        if len(matches) == 1:
            return matches.pop()
        if len(matches) > 1:
            return None
    if len(candidate.port_signature) >= 2:
        matches = {e.device_id for e in others if e.is_random_mac and e.port_signature == candidate.port_signature}
        if len(matches) == 1:
            return matches.pop()
    return None


# ------------------------------------------------------------ Tarama farkı


def diff_snapshots(prev: dict, cur: dict) -> list[dict]:
    """Snapshot formatı: {device_key: {"name", "ip", "os", "ports": {"tcp/22": "ssh OpenSSH 9"}, "findings": {key: {"title", "severity"}}}}"""
    changes: list[dict] = []

    def add(dev_key, name, kind, detail, severity="info"):
        changes.append({"device": dev_key, "name": name, "kind": kind, "detail": detail, "severity": severity})

    for key in sorted(set(prev) | set(cur)):
        p, c = prev.get(key), cur.get(key)
        name = (c or p or {}).get("name") or key
        if p is None:
            add(key, name, "device_added", f"Yeni cihaz ({c.get('ip')})", "low")
            p = {"ports": {}, "findings": {}, "os": None}
        if c is None:
            add(key, name, "device_missing", f"Bu taramada bulunamadı (son IP {p.get('ip')})")
            continue
        pp, cp = p.get("ports", {}), c.get("ports", {})
        for port in sorted(set(cp) - set(pp)):
            add(key, name, "port_opened", f"{port} açıldı: {cp[port]}".rstrip(": "), "medium")
        for port in sorted(set(pp) - set(cp)):
            add(key, name, "port_closed", f"{port} kapandı")
        for port in sorted(set(pp) & set(cp)):
            if pp[port] != cp[port] and pp[port] and cp[port]:
                add(key, name, "service_changed", f"{port}: {pp[port]} → {cp[port]}")
        if p.get("os") and c.get("os") and p.get("os") != c.get("os"):
            add(key, name, "os_changed", f"{p['os']} → {c['os']}")
        if p.get("ip") and c.get("ip") and p.get("ip") != c.get("ip"):
            add(key, name, "ip_changed", f"{p['ip']} → {c['ip']}")
        pf, cf = p.get("findings", {}), c.get("findings", {})
        for fk in sorted(set(cf) - set(pf)):
            add(key, name, "finding_new", cf[fk]["title"], cf[fk]["severity"])
        for fk in sorted(set(pf) - set(cf)):
            add(key, name, "finding_resolved", pf[fk]["title"])
    return changes


# ------------------------------------------------------------ Güvenlik skoru

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
PER_DEVICE_CAP = 40


def security_score(findings: Iterable[tuple[int | None, str]]) -> int:
    """findings: (device_id, severity) çiftleri; çözülmüş/yoksayılmış olanlar dahil edilmemeli."""
    per_device: dict[int | None, int] = {}
    for device_id, severity in findings:
        per_device[device_id] = per_device.get(device_id, 0) + SEVERITY_WEIGHTS.get(severity, 0)
    penalty = sum(min(v, PER_DEVICE_CAP) for v in per_device.values())
    return max(0, 100 - penalty)


def score_grade(score: int) -> tuple[str, str]:
    if score >= 90:
        return "A", "Çok iyi"
    if score >= 75:
        return "B", "İyi"
    if score >= 55:
        return "C", "Orta"
    if score >= 35:
        return "D", "Zayıf"
    return "F", "Kritik"


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0
