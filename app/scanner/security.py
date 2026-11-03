"""Kural tabanlı güvenlik bulguları (nmap port/servis + NSE script çıktılarından)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.scanner.nmapxml import HostResult, PortResult


@dataclass
class FindingData:
    """Bir güvenlik bulgusu. Metinler ``msg`` katalog kimliği + ``params`` ile i18n'den üretilir."""

    rule: str  # anahtar (dedupe) kuralı, ör. "database"
    severity: str
    msg: str  # i18n kimliği, ör. "redis" -> f.redis.title
    params: dict = field(default_factory=dict)
    port: int | None = None
    source: str = "rule"
    cves: list[dict] = field(default_factory=list)
    ident: str | None = None  # aynı kural+port için ayırt edici ek (ör. UPnP yönlendirmesi)

    @property
    def key_rule(self) -> str:
        return f"{self.rule}-{self.ident}" if self.ident else self.rule

    def text(self, field_name: str, lang: str = "tr") -> str:
        from app.i18n import tl

        return tl(lang, f"f.{self.msg}.{field_name}", **self.params)

    @property
    def title(self) -> str:
        return self.text("title")

    @property
    def description(self) -> str:
        return self.text("desc")

    @property
    def remediation(self) -> str:
        return self.text("fix")


# port -> (kural, önem, mesaj kimliği)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    23: ("telnet", "high", "telnet"),
    2323: ("telnet", "high", "telnet-alt"),
    21: ("ftp", "medium", "ftp"),
    2375: ("docker-api", "critical", "docker-api"),
    5900: ("vnc", "medium", "vnc"),
    5901: ("vnc", "medium", "vnc"),
    3389: ("rdp", "low", "rdp"),
    1883: ("mqtt", "medium", "mqtt"),
    6379: ("database", "medium", "redis"),
    27017: ("database", "medium", "mongodb"),
    9200: ("database", "medium", "elasticsearch"),
    11211: ("database", "medium", "memcached"),
    3306: ("database", "low", "mysql"),
    5432: ("database", "low", "postgres"),
    554: ("rtsp", "low", "rtsp"),
    7547: ("tr069", "medium", "tr069"),
}

SEVERITY_FROM_CVSS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low")]

_DATE_RE = re.compile(r"Not valid after:\s*(\S+)")
_SUBJ_RE = re.compile(r"Subject:\s*(.+)")
_ISSUER_RE = re.compile(r"Issuer:\s*(.+)")


def _parse_nmap_date(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:19] if "T" in value else value[:10], fmt)
        except ValueError:
            continue
    return None


def cert_findings(port: PortResult, now: datetime | None = None) -> list[FindingData]:
    out = port.scripts.get("ssl-cert")
    if not out:
        return []
    now = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
    findings: list[FindingData] = []
    m = _DATE_RE.search(out)
    if m:
        expires = _parse_nmap_date(m.group(1))
        if expires and expires < now:
            findings.append(FindingData("tls-expired", "medium", "tls-expired", {"port": port.port, "date": f"{expires:%Y-%m-%d}"}, port.port, "nse"))
        elif expires and expires < now + timedelta(days=30):
            findings.append(FindingData("tls-expiring", "low", "tls-expiring", {"port": port.port, "date": f"{expires:%Y-%m-%d}"}, port.port, "nse"))
    subj, issuer = _SUBJ_RE.search(out), _ISSUER_RE.search(out)
    if subj and issuer and subj.group(1).strip() == issuer.group(1).strip():
        findings.append(FindingData("tls-selfsigned", "info", "tls-selfsigned", {"port": port.port}, port.port, "nse"))
    return findings


def vulners_finding(port: PortResult) -> FindingData | None:
    rows = port.script_tables.get("vulners") or []
    cves = []
    for row in rows:
        vid = row.get("id")
        if not vid:
            continue
        try:
            cvss = float(row.get("cvss") or 0)
        except ValueError:
            cvss = 0.0
        cves.append({"id": vid, "cvss": cvss, "type": row.get("type", ""), "exploit": row.get("is_exploit") == "true"})
    if not cves:
        return None
    cves.sort(key=lambda c: c["cvss"], reverse=True)
    top = cves[0]["cvss"]
    severity = next(sev for threshold, sev in SEVERITY_FROM_CVSS if top >= threshold)
    product = " ".join(x for x in [port.product, port.version] if x) or port.service or f"port {port.port}"
    exploits = sum(1 for c in cves if c["exploit"])
    return FindingData(
        "vulners", severity, "vulners", {"product": product, "count": len(cves), "top": top, "exploits": exploits},
        port.port, "nse", cves[:25],
    )


def analyze_host(host: HostResult, is_gateway: bool = False, now: datetime | None = None) -> list[FindingData]:
    findings: list[FindingData] = []
    open_ports = host.open_ports

    for p in open_ports:
        rule = RISKY_PORTS.get(p.port)
        if rule and not (p.port == 21 and p.tunnel == "ssl"):
            name, sev, msg = rule
            findings.append(FindingData(name, sev, msg, {}, p.port))

        if "ftp-anon" in p.scripts and "Anonymous FTP login allowed" in p.scripts["ftp-anon"]:
            findings.append(FindingData("ftp-anon", "high", "ftp-anon", {}, p.port, "nse"))

        smb = p.scripts.get("smb-protocols", "")
        if "NT LM 0.12" in smb or "SMBv1" in smb:
            findings.append(FindingData("smbv1", "high", "smbv1", {}, p.port, "nse"))

        if p.scripts.get("http-default-accounts", "").strip():
            findings.append(FindingData("default-creds", "critical", "default-creds",
                                        {"accounts": p.scripts["http-default-accounts"].strip()[:400]}, p.port, "nse"))

        findings.extend(cert_findings(p, now))

        vf = vulners_finding(p)
        if vf:
            findings.append(vf)

    if is_gateway:
        http_ports = {p.port for p in open_ports if (p.service or "").startswith("http") and p.tunnel != "ssl" and p.service != "https"}
        https_ports = {p.port for p in open_ports if p.tunnel == "ssl" or p.service == "https" or p.port == 443}
        if http_ports and not https_ports:
            findings.append(FindingData("router-http", "low", "router-http", {}, min(http_ports)))
    return findings
