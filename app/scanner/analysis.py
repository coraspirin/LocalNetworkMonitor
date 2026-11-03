"""Saf analiz fonksiyonları: gizli MAC eşleştirme, tarama farkı (diff), güvenlik skoru."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from app.models import SEVERITIES

# ------------------------------------------------------------ gizli MAC eşleştirme

# Herkeste aynı olabilen, kimlik belirtmeyen adlar
GENERIC_NAMES = {
    "", "android", "localhost", "unknown", "iphone", "ipad", "ipod", "macbook", "macbookpro", "macbookair", "imac",
    "espressif", "esp", "galaxy", "samsung", "pixel", "xiaomi", "redmi", "huawei", "oneplus", "phone", "mobile",
    "applewatch", "watch", "appletv", "homepod", "laptop", "desktop", "pc", "tv",
}

AUTO_MERGE_SCORE = 70
SUGGEST_SCORE = 40
TIMING_WINDOW = timedelta(hours=2)

WEIGHTS = {
    "name": 70,
    "name_mismatch": -40,
    "dhcp_fp": 20,
    "dhcp_fp_mismatch": -30,
    "ports": 10,
    "ports_mismatch": -10,
    "os_family": 5,
    "os_family_mismatch": -50,
    "type": 5,
    "timing": 15,
}


@dataclass
class Identity:
    """Bir cihazı MAC'ten bağımsız tanımlayan ipuçları."""

    device_id: int | None
    hostname: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None
    dhcp_hostname: str | None = None
    service_names: tuple[str, ...] = ()
    port_signature: frozenset[int] = frozenset()
    is_random_mac: bool = False
    dhcp_fp: str | None = None
    os_family: str | None = None
    device_type: str | None = None
    present: bool = False  # bu taramada (aynı anda) görüldü
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def names(self) -> set[str]:
        out = {normalize_name(n) for n in (self.mdns_name, self.hostname, self.netbios_name, self.dhcp_hostname, *self.service_names)}
        return {n for n in out if n}


@dataclass
class MatchCandidate:
    device_id: int
    score: int
    reasons: list[str] = field(default_factory=list)


def normalize_name(name: str | None) -> str | None:
    """'Aylin’s iPhone', 'Aylins-iPhone.local', 'aylins-iphone.lan' -> 'aylinsiphone'."""
    if not name:
        return None
    n = unicodedata.normalize("NFKC", name).strip().lower().rstrip(".")
    if "@" in n:  # _raop örnek adı: "A1B2C3D4E5F6@Aylin's iPhone"
        n = n.split("@", 1)[1]
    for suffix in (".local", ".lan", ".home", ".fritz.box", ".localdomain", ".home.arpa", ".station", ".router"):
        n = n.removesuffix(suffix)
    n = re.sub(r"[^\w]|_", "", n)
    if n in GENERIC_NAMES or len(n) < 3:
        return None
    return n


def score_pair(cand: Identity, other: Identity) -> MatchCandidate | None:
    """İki kimliğin aynı fiziksel cihaz olma ihtimalini puanlar. Kesin olarak farklıysa None."""
    if other.device_id is None or other.device_id == cand.device_id:
        return None
    if other.present:  # ikisi aynı anda ağda: aynı cihaz olamaz
        return None
    reasons: list[str] = []
    score = 0
    cn, on = cand.names(), other.names()
    name_match = bool(cn & on)
    if name_match:
        score += WEIGHTS["name"]
        reasons.append("name")
    elif cn and on:
        score += WEIGHTS["name_mismatch"]
    # isim eşleşmesi yoksa yalnızca gizli MAC'li kayıtlar arasında tahmin yürüt
    if not name_match and not (cand.is_random_mac and other.is_random_mac):
        return None

    if cand.dhcp_fp and other.dhcp_fp:
        if cand.dhcp_fp == other.dhcp_fp:
            score += WEIGHTS["dhcp_fp"]
            reasons.append("dhcp_fp")
        else:
            score += WEIGHTS["dhcp_fp_mismatch"]
    if cand.port_signature and other.port_signature:
        if cand.port_signature == other.port_signature:
            score += WEIGHTS["ports"]
            reasons.append("ports")
        else:
            score += WEIGHTS["ports_mismatch"]
    if cand.os_family and other.os_family:
        if cand.os_family == other.os_family:
            score += WEIGHTS["os_family"]
            reasons.append("os_family")
        else:
            score += WEIGHTS["os_family_mismatch"]
    elif cand.device_type and cand.device_type == other.device_type and cand.device_type != "unknown":
        score += WEIGHTS["type"]
        reasons.append("type")
    if cand.first_seen and other.last_seen and timedelta(0) <= cand.first_seen - other.last_seen <= TIMING_WINDOW:
        score += WEIGHTS["timing"]
        reasons.append("timing")
    return MatchCandidate(other.device_id, score, reasons)


def score_identity_candidates(candidate: Identity, existing: Iterable[Identity], limit: int = 3) -> list[MatchCandidate]:
    """Gizli MAC'li yeni kayıt için en olası eşleşmeler (yüksek skordan düşüğe, en az SUGGEST_SCORE)."""
    if not candidate.is_random_mac:
        return []
    scored = [m for m in (score_pair(candidate, e) for e in existing) if m and m.score >= SUGGEST_SCORE]
    scored.sort(key=lambda m: m.score, reverse=True)
    return scored[:limit]


def decide(matches: list[MatchCandidate]) -> tuple[str, list[MatchCandidate]]:
    """('merge', [tek]) | ('suggest', adaylar) | ('none', [])."""
    if not matches:
        return "none", []
    top = matches[0]
    clear_winner = len(matches) == 1 or matches[1].score <= top.score - 20
    if top.score >= AUTO_MERGE_SCORE and clear_winner:
        return "merge", [top]
    return "suggest", matches


def find_identity_match(candidate: Identity, existing: Iterable[Identity]) -> int | None:
    """Geriye dönük uyumluluk: yalnızca otomatik birleştirilecek eşleşmeyi döndürür."""
    action, matches = decide(score_identity_candidates(candidate, existing))
    return matches[0].device_id if action == "merge" else None


# ------------------------------------------------------------ Tarama farkı


def diff_snapshots(prev: dict, cur: dict) -> list[dict]:
    """Snapshot formatı: {device_key: {"name", "ip", "os", "ports": {"tcp/22": "ssh OpenSSH 9"},
    "findings": {key: {"title", "severity", "msg_id", "params"}}}}

    Her değişiklik dil bağımsız ``params`` taşır (metin i18n.diff_text ile üretilir);
    ``detail`` Türkçe yedek metindir.
    """
    changes: list[dict] = []

    def add(dev_key, name, kind, detail, params, severity="info"):
        changes.append({"device": dev_key, "name": name, "kind": kind, "detail": detail, "params": params, "severity": severity})

    def fparams(f: dict) -> dict:
        return {"msg_id": f.get("msg_id"), "fparams": f.get("params") or {}, "title": f.get("title", "")}

    for key in sorted(set(prev) | set(cur)):
        p, c = prev.get(key), cur.get(key)
        name = (c or p or {}).get("name") or key
        if p is None:
            add(key, name, "device_added", f"Yeni cihaz ({c.get('ip')})", {"ip": c.get("ip")}, "low")
            p = {"ports": {}, "findings": {}, "os": None}
        if c is None:
            add(key, name, "device_missing", f"Bu taramada bulunamadı (son IP {p.get('ip')})", {"ip": p.get("ip")})
            continue
        pp, cp = p.get("ports", {}), c.get("ports", {})
        for port in sorted(set(cp) - set(pp)):
            add(key, name, "port_opened", f"{port} açıldı: {cp[port]}".rstrip(": "), {"port": port, "service": cp[port] or "?"}, "medium")
        for port in sorted(set(pp) - set(cp)):
            add(key, name, "port_closed", f"{port} kapandı", {"port": port})
        for port in sorted(set(pp) & set(cp)):
            if pp[port] != cp[port] and pp[port] and cp[port]:
                add(key, name, "service_changed", f"{port}: {pp[port]} → {cp[port]}", {"port": port, "old": pp[port], "new": cp[port]})
        if p.get("os") and c.get("os") and p.get("os") != c.get("os"):
            add(key, name, "os_changed", f"{p['os']} → {c['os']}", {"old": p["os"], "new": c["os"]})
        if p.get("ip") and c.get("ip") and p.get("ip") != c.get("ip"):
            add(key, name, "ip_changed", f"{p['ip']} → {c['ip']}", {"old": p["ip"], "new": c["ip"]})
        pf, cf = p.get("findings", {}), c.get("findings", {})
        for fk in sorted(set(cf) - set(pf)):
            add(key, name, "finding_new", cf[fk]["title"], fparams(cf[fk]), cf[fk]["severity"])
        for fk in sorted(set(pf) - set(cf)):
            add(key, name, "finding_resolved", pf[fk]["title"], fparams(pf[fk]))
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
    """(harf, i18n anahtarı)"""
    if score >= 90:
        return "A", "grade.A"
    if score >= 75:
        return "B", "grade.B"
    if score >= 55:
        return "C", "grade.C"
    if score >= 35:
        return "D", "grade.D"
    return "F", "grade.F"


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0
