"""MAC OUI -> üretici. nmap ile gelen çevrimdışı ``nmap-mac-prefixes`` dosyasını kullanır."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.netutil import is_random_mac, normalize_mac

CANDIDATE_FILES = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/local/share/nmap/nmap-mac-prefixes"),
]


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    for path in CANDIDATE_FILES:
        if not path.exists():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            prefix, _, name = line.partition(" ")
            if name:
                table[prefix.strip().upper()] = name.strip()
        break
    return table


def lookup(mac: str | None) -> str | None:
    mac = normalize_mac(mac)
    if not mac:
        return None
    if is_random_mac(mac):
        return None
    hexmac = mac.replace(":", "").upper()
    table = _table()
    # nmap dosyası 6, 7 ve 9 haneli önekler içerir; en uzun eşleşme kazanır
    for length in (9, 7, 6):
        name = table.get(hexmac[:length])
        if name:
            return name
    return None
