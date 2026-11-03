"""Kural tabanlı güvenlik bulguları (nmap port/servis + NSE script çıktılarından)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.scanner.nmapxml import HostResult, PortResult


@dataclass
class FindingData:
    rule: str
    severity: str
    title: str
    description: str
    remediation: str
    port: int | None = None
    source: str = "rule"
    cves: list[dict] = field(default_factory=list)

    def key(self, device_key: str) -> str:
        return f"{self.rule}:{device_key}:{self.port if self.port is not None else '-'}"


# port -> (rule, severity, title, description, remediation)
RISKY_PORTS: dict[int, tuple[str, str, str, str, str]] = {
    23: ("telnet", "high", "Telnet açık", "Telnet trafiği (şifreler dahil) şifrelenmeden iletilir.", "Telnet'i kapatın, gerekiyorsa SSH kullanın. IoT cihazlarda firmware güncellemesi yapın."),
    2323: ("telnet", "high", "Telnet (alternatif port) açık", "Mirai gibi IoT botnetlerinin hedeflediği alternatif Telnet portu.", "Cihazın yönetim arayüzünden Telnet'i kapatın ve firmware'i güncelleyin."),
    21: ("ftp", "medium", "Şifrelenmemiş FTP", "FTP kimlik bilgilerini düz metin olarak iletir.", "SFTP/FTPS kullanın veya FTP servisini kapatın."),
    2375: ("docker-api", "critical", "Şifresiz Docker API açık", "Docker daemon API'si kimlik doğrulamasız erişime açık; host üzerinde tam yetki sağlar.", "Docker API'yi yalnızca unix soketinden dinleyin veya TLS (2376) ile koruyun."),
    5900: ("vnc", "medium", "VNC açık", "Uzak masaüstü erişimi; zayıf şifreler sıklıkla istismar edilir.", "VNC'yi kullanmıyorsanız kapatın, güçlü şifre ve mümkünse SSH tüneli kullanın."),
    5901: ("vnc", "medium", "VNC açık", "Uzak masaüstü erişimi; zayıf şifreler sıklıkla istismar edilir.", "VNC'yi kullanmıyorsanız kapatın, güçlü şifre ve mümkünse SSH tüneli kullanın."),
    3389: ("rdp", "low", "RDP (Uzak Masaüstü) açık", "Windows Uzak Masaüstü ağda erişilebilir.", "Gerekmiyorsa kapatın; Ağ Düzeyinde Kimlik Doğrulama (NLA) açık olsun, internete asla yönlendirmeyin."),
    1883: ("mqtt", "medium", "Şifrelenmemiş MQTT", "MQTT broker'ı TLS olmadan çalışıyor; kimlik doğrulaması kapalı olabilir.", "Kimlik doğrulamayı açın ve 8883 (TLS) portunu kullanın."),
    6379: ("database", "medium", "Redis ağda açık", "Redis varsayılan olarak kimlik doğrulamasızdır.", "Redis'i yalnızca localhost'ta dinletin veya 'requirepass' ayarlayın."),
    27017: ("database", "medium", "MongoDB ağda açık", "Veritabanı ağdaki tüm cihazlara açık.", "bindIp ile erişimi sınırlayın ve kimlik doğrulamayı açın."),
    9200: ("database", "medium", "Elasticsearch ağda açık", "Elasticsearch HTTP API'si ağa açık.", "Güvenlik özelliklerini (xpack.security) açın veya erişimi sınırlayın."),
    11211: ("database", "medium", "Memcached ağda açık", "Memcached kimlik doğrulaması içermez.", "Yalnızca localhost'ta dinletin."),
    3306: ("database", "low", "MySQL/MariaDB ağda açık", "Veritabanı portu ağdaki cihazlara açık.", "Gerekmiyorsa bind-address=127.0.0.1 kullanın."),
    5432: ("database", "low", "PostgreSQL ağda açık", "Veritabanı portu ağdaki cihazlara açık.", "listen_addresses ve pg_hba.conf ile erişimi sınırlayın."),
    554: ("rtsp", "low", "RTSP video yayını açık", "Kamera/medya yayını ağda erişilebilir; çoğu kamera zayıf varsayılan şifre kullanır.", "Kameranın varsayılan şifresini değiştirin, firmware'i güncelleyin."),
    7547: ("tr069", "medium", "TR-069 (CWMP) yönetim portu açık", "ISS uzaktan yönetim protokolü; geçmişte ciddi zafiyetler barındırdı.", "Router firmware'ini güncel tutun; mümkünse TR-069'u kapatın."),
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
            findings.append(
                FindingData("tls-expired", "medium", "TLS sertifikasının süresi dolmuş",
                            f"Port {port.port} sertifikası {expires:%Y-%m-%d} tarihinde sona ermiş.",
                            "Sertifikayı yenileyin (ör. cihaz firmware'i veya Let's Encrypt).", port.port, "nse")
            )
        elif expires and expires < now + timedelta(days=30):
            findings.append(
                FindingData("tls-expiring", "low", "TLS sertifikası yakında sona eriyor",
                            f"Port {port.port} sertifikası {expires:%Y-%m-%d} tarihinde sona erecek.",
                            "Sertifikayı süresi dolmadan yenileyin.", port.port, "nse")
            )
    subj, issuer = _SUBJ_RE.search(out), _ISSUER_RE.search(out)
    if subj and issuer and subj.group(1).strip() == issuer.group(1).strip():
        findings.append(
            FindingData("tls-selfsigned", "info", "Kendinden imzalı TLS sertifikası",
                        f"Port {port.port} kendinden imzalı sertifika kullanıyor; tarayıcı uyarıları ortadan aradaki adam saldırılarını ayırt etmeyi zorlaştırır.",
                        "Mümkünse güvenilir bir CA'dan sertifika kullanın.", port.port, "nse")
        )
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
        "vulners", severity, f"Bilinen zafiyetler: {product}",
        f"{len(cves)} bilinen zafiyet (en yüksek CVSS {top}). Açık exploit sayısı: {exploits}.",
        "Yazılımı/firmware'i en güncel sürüme yükseltin.", port.port, "nse", cves[:25],
    )


def analyze_host(host: HostResult, is_gateway: bool = False, now: datetime | None = None) -> list[FindingData]:
    findings: list[FindingData] = []
    open_ports = host.open_ports

    for p in open_ports:
        rule = RISKY_PORTS.get(p.port)
        if rule and not (p.port == 21 and p.tunnel == "ssl"):
            name, sev, title, desc, rem = rule
            findings.append(FindingData(name, sev, title, desc, rem, p.port))

        if "ftp-anon" in p.scripts and "Anonymous FTP login allowed" in p.scripts["ftp-anon"]:
            findings.append(FindingData("ftp-anon", "high", "Anonim FTP girişi açık",
                                        "Kimlik doğrulaması olmadan FTP sunucusundaki dosyalara erişilebiliyor.",
                                        "Anonim erişimi kapatın.", p.port, "nse"))

        smb = p.scripts.get("smb-protocols", "")
        if "NT LM 0.12" in smb or "SMBv1" in smb:
            findings.append(FindingData("smbv1", "high", "SMBv1 etkin",
                                        "Eski SMBv1 protokolü WannaCry/EternalBlue gibi saldırılara açıktır.",
                                        "SMBv1'i devre dışı bırakın (Windows: 'SMB 1.0/CIFS Dosya Paylaşımı Desteği' özelliğini kaldırın).",
                                        p.port, "nse"))

        if p.scripts.get("http-default-accounts", "").strip():
            findings.append(FindingData("default-creds", "critical", "Varsayılan şifre ile giriş yapılabiliyor",
                                        "Web arayüzü bilinen varsayılan kullanıcı adı/şifre ile erişime açık:\n" + p.scripts["http-default-accounts"].strip()[:400],
                                        "Varsayılan şifreyi hemen değiştirin.", p.port, "nse"))

        findings.extend(cert_findings(p, now))

        vf = vulners_finding(p)
        if vf:
            findings.append(vf)

    if is_gateway:
        http_ports = {p.port for p in open_ports if (p.service or "").startswith("http") and p.tunnel != "ssl" and p.service != "https"}
        https_ports = {p.port for p in open_ports if p.tunnel == "ssl" or p.service == "https" or p.port == 443}
        if http_ports and not https_ports:
            findings.append(FindingData("router-http", "low", "Router yönetim paneli şifrelenmemiş HTTP üzerinden",
                                        "Yönetim şifresi ağda düz metin olarak iletilir.",
                                        "Router ayarlarından HTTPS yönetimini etkinleştirin.", min(http_ports)))
    return findings
