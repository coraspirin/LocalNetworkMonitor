"""DHCP parmak izinden işletim sistemi ailesi tahmini.

İstemcilerin DHCP isteğinde gönderdiği "parameter request list" (option 55) ve
"vendor class" (option 60) değerleri işletim sistemine göre karakteristiktir ve
MAC adresi değişse bile aynı kalır. Bu tablo kaba bir sınıflandırma yapar
(sürüm ayrımı hedeflenmez).
"""

from __future__ import annotations

FAMILIES = ("apple", "android", "windows", "linux", "embedded")


def os_family(prl: str | None, vendor_class: str | None = None) -> str | None:
    vc = (vendor_class or "").lower()
    if vc.startswith("android-dhcp") or "android" in vc:
        return "android"
    if vc.startswith("msft"):
        return "windows"
    if vc.startswith("udhcp"):
        return "embedded"
    if vc.startswith("dhcpcd"):
        # dhcpcd hem Android'in eski sürümlerinde hem Linux'ta kullanılır
        return "android" if "android" in vc else "linux"

    if not prl:
        return None
    try:
        opts = [int(x) for x in prl.split(",") if x.strip()]
    except ValueError:
        return None
    s = set(opts)

    # Apple (iOS, iPadOS, macOS): 1,121,3,6,15,(108,114,)119,252,95,44,46
    if opts[:2] == [1, 121] and {119, 252} <= s and 95 in s:
        return "apple"
    # Windows: 1,3,6,15,31,33,43,44,46,47,119,121,249,252
    if {31, 33, 249} <= s and {43, 44, 46, 47} <= s:
        return "windows"
    # Android (Google DHCP istemcisi): 1,3,6,15,26,28,51,58,59,43(,114,108)
    if {26, 28, 51, 58, 59} <= s and 43 in s:
        return "android"
    # ISC dhclient / NetworkManager / systemd-networkd
    if {1, 28, 2, 3, 15, 6} <= s and (12 in s or 42 in s or 119 in s):
        return "linux"
    # BusyBox udhcpc (çoğu IoT / gömülü cihaz): kısa listeler
    if s <= {1, 3, 6, 12, 15, 28, 42, 43, 44, 51, 54, 58, 59, 119, 121} and len(s) <= 8 and 1 in s and 3 in s:
        return "embedded"
    return None
