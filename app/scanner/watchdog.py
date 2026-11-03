"""Sürekli izleme: ARP spoofing, sahte (rogue) DHCP sunucusu tespiti ve pasif DHCP parmak izi toplama."""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from app.netutil import normalize_mac

log = logging.getLogger(__name__)

ALERT_COOLDOWN_S = 3600
# Kendi DHCP yoklamalarımızın sahte MAC'leri (pasif dinlemede yok sayılır)
PROBE_MACS: set[str] = set()


@dataclass
class Alert:
    kind: str  # arp_spoof, rogue_dhcp, ip_mac_changed
    severity: str
    msg: str  # i18n kimliği: ev.<msg>
    params: dict = field(default_factory=dict)
    ip: str | None = None
    mac: str | None = None

    @property
    def message(self) -> str:
        from app.i18n import tl

        return tl("tr", f"ev.{self.msg}", **self.params)


class ArpDetector:
    """ARP yanıtlarından IP->MAC eşlemesini takip eder (saf mantık; test edilebilir)."""

    def __init__(self, gateway_ip: str | None = None, gateway_mac: str | None = None, known: dict[str, str] | None = None):
        self.gateway_ip = gateway_ip
        self.gateway_mac = normalize_mac(gateway_mac)
        self.table: dict[str, str] = {ip: normalize_mac(m) for ip, m in (known or {}).items() if normalize_mac(m)}
        self._last_alert: dict[tuple, float] = {}

    def _cooldown_ok(self, key: tuple, now: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and now - last < ALERT_COOLDOWN_S:
            return False
        self._last_alert[key] = now
        return True

    def observe(self, ip: str, mac: str, now: float | None = None) -> list[Alert]:
        now = time.time() if now is None else now
        mac = normalize_mac(mac)
        if not ip or not mac or ip == "0.0.0.0":
            return []
        alerts: list[Alert] = []

        if self.gateway_ip and ip == self.gateway_ip:
            if self.gateway_mac is None:
                self.gateway_mac = mac
            elif mac != self.gateway_mac:
                if self._cooldown_ok(("gw", mac), now):
                    alerts.append(Alert("arp_spoof", "critical", "arp_spoof",
                                        {"ip": ip, "mac": mac, "expected": self.gateway_mac}, ip, mac))
                return alerts  # gateway tablosunu saldırgan MAC ile güncelleme

        previous = self.table.get(ip)
        if previous and previous != mac:
            if self._cooldown_ok(("ipmac", ip, mac), now):
                alerts.append(Alert("ip_mac_changed", "info", "ip_mac_changed", {"ip": ip, "old": previous, "new": mac}, ip, mac))
        self.table[ip] = mac
        return alerts

    def accept_gateway_mac(self, mac: str) -> None:
        """Kullanıcı yeni gateway MAC'ini meşru kabul ettiğinde (ör. router değişimi)."""
        self.gateway_mac = normalize_mac(mac)
        if self.gateway_ip and self.gateway_mac:
            self.table[self.gateway_ip] = self.gateway_mac


def evaluate_dhcp_offers(offers: list[dict], expected_server: str | None) -> list[Alert]:
    """offers: [{"server_id": ip, "src_mac": mac, "offered_ip": ip}]"""
    servers = sorted({o["server_id"] for o in offers if o.get("server_id")})
    alerts: list[Alert] = []
    if len(servers) > 1:
        alerts.append(Alert("rogue_dhcp", "high", "rogue_dhcp_multi", {"servers": ", ".join(servers)}, servers[-1]))
    elif servers and expected_server and servers[0] != expected_server:
        alerts.append(Alert("rogue_dhcp", "high", "rogue_dhcp_unexpected", {"server": servers[0], "expected": expected_server}, servers[0]))
    return alerts


# ------------------------------------------------------------------ pasif DHCP parmak izi
@dataclass
class DhcpInfo:
    mac: str
    hostname: str | None = None
    vendor_class: str | None = None
    prl: str | None = None  # "1,121,3,6,..."
    client_id: str | None = None


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    value = str(value).strip().strip("\x00")
    return value[:80] or None


def parse_dhcp_options(mac: str, options: list) -> DhcpInfo | None:
    """scapy DHCP seçenek listesinden ([('message-type', 3), ('hostname', b'x'), ...]) istemci bilgisi çıkarır.

    Yalnızca istemci mesajları (DISCOVER=1, REQUEST=3, INFORM=8) değerlendirilir.
    """
    mac = normalize_mac(mac)
    if not mac:
        return None
    opts = {o[0]: o[1] for o in options if isinstance(o, tuple) and len(o) >= 2}
    if opts.get("message-type") not in (1, 3, 8):
        return None
    prl = opts.get("param_req_list")
    if isinstance(prl, (bytes, bytearray)):
        prl = list(prl)
    if isinstance(prl, int):
        prl = [prl]
    cid = opts.get("client_id")
    return DhcpInfo(
        mac=mac,
        hostname=_text(opts.get("hostname")),
        vendor_class=_text(opts.get("vendor_class_id")),
        prl=",".join(str(int(x)) for x in prl) if prl else None,
        client_id=cid.hex() if isinstance(cid, (bytes, bytearray)) else _text(cid),
    )


def dhcp_info_from_packet(pkt) -> DhcpInfo | None:
    from scapy.all import BOOTP, DHCP

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP) or pkt[BOOTP].op != 1:
        return None
    chaddr = bytes(pkt[BOOTP].chaddr)[:6]
    mac = ":".join(f"{b:02x}" for b in chaddr)
    if mac in PROBE_MACS:
        return None
    return parse_dhcp_options(mac, pkt[DHCP].options)


def dhcp_probe(iface: str | None = None, timeout: float = 5.0) -> list[dict]:
    """DHCP DISCOVER yayınlayıp gelen OFFER'ları toplar (kiralama oluşturmaz)."""
    from scapy.all import BOOTP, DHCP, IP, UDP, AsyncSniffer, Ether, conf, sendp

    conf.checkIPaddr = False
    fake_mac = "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))
    PROBE_MACS.add(fake_mac)
    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = bytes.fromhex(fake_mac.replace(":", "")) + b"\x00" * 10
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6]), "end"])
    )
    offers: list[dict] = []

    def _handle(p):
        if not p.haslayer(BOOTP) or p[BOOTP].xid != xid or not p.haslayer(DHCP):
            return
        opts = {o[0]: o[1] for o in p[DHCP].options if isinstance(o, tuple) and len(o) >= 2}
        if opts.get("message-type") != 2:  # OFFER
            return
        offers.append({"server_id": opts.get("server_id") or p[IP].src, "src_mac": p[Ether].src, "offered_ip": p[BOOTP].yiaddr})

    sniffer = AsyncSniffer(filter="udp and (port 67 or port 68)", prn=_handle, store=False, iface=iface)
    sniffer.start()
    time.sleep(0.3)
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(timeout)
    sniffer.stop()
    return offers


class ArpWatcher:
    """Arka planda ARP ve DHCP paketlerini dinler; uyarıları ve DHCP gözlemlerini geri çağırımla iletir."""

    def __init__(self, detector: ArpDetector, on_alert: Callable[[Alert], None], iface: str | None = None,
                 on_dhcp: Callable[[DhcpInfo], None] | None = None):
        self.detector = detector
        self.on_alert = on_alert
        self.on_dhcp = on_dhcp
        self.iface = iface
        self._sniffer = None
        self._lock = threading.Lock()

    def _handle(self, pkt) -> None:
        from scapy.all import ARP

        if pkt.haslayer(ARP):
            if pkt[ARP].op != 2:  # yalnızca is-at (yanıt)
                return
            with self._lock:
                alerts = self.detector.observe(pkt[ARP].psrc, pkt[ARP].hwsrc)
            for a in alerts:
                try:
                    self.on_alert(a)
                except Exception:  # pragma: no cover
                    log.exception("ARP uyarısı işlenemedi")
            return
        if self.on_dhcp is not None:
            try:
                info = dhcp_info_from_packet(pkt)
                if info:
                    self.on_dhcp(info)
            except Exception:  # pragma: no cover
                log.exception("DHCP paketi işlenemedi")

    def start(self) -> bool:
        try:
            from scapy.all import AsyncSniffer

            flt = "arp or (udp and (port 67 or port 68))" if self.on_dhcp else "arp"
            self._sniffer = AsyncSniffer(filter=flt, prn=self._handle, store=False, iface=self.iface)
            self._sniffer.start()
            log.info("ARP/DHCP izleyici başlatıldı (%s)", self.iface or "varsayılan arayüz")
            return True
        except Exception as exc:
            log.warning("ARP izleyici başlatılamadı: %s", exc)
            self._sniffer = None
            return False

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None and getattr(self._sniffer, "running", False)
