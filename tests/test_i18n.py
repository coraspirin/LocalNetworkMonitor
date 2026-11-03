"""Çok dillilik: katalog bütünlüğü, şablon anahtarları, İngilizce sayfalar ve kayıtlı metinlerin çevirisi."""

import json
import re
import string
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app import i18n
from app.models import Device, DeviceAlias, DeviceEvent, Finding, MergeSuggestion, Port, Scan, Subnet

APP = Path(__file__).parent.parent / "app"
TURKISH_CHARS = re.compile(r"[çğışöüÇĞİŞÖÜ]")


def _fields(text: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(text) if f}


def test_catalog_placeholders_match():
    for key, (tr, en) in i18n.M.items():
        assert _fields(tr) == _fields(en), key
        assert tr and en, key


def test_every_used_key_exists():
    used: set[str] = set()
    pattern = re.compile(r"""\bt\(\s*['"]([a-z_][\w.\-]*)['"]""")
    for path in list(APP.rglob("*.html")) + list(APP.rglob("*.py")):
        used |= set(pattern.findall(path.read_text()))
    js_pattern = re.compile(r"""NS\.t\(\s*["']([\w]+)["']|[^.\w]t\(\s*["']([\w]+)["']""")
    js_used = set()
    for path in list(APP.rglob("*.js")) + list(APP.rglob("*.html")):
        for a, b in js_pattern.findall(path.read_text()):
            js_used.add(a or b)
    # "evk." gibi önekler dinamik anahtarlardır (test_dynamic_key_families_complete kapsar)
    missing = sorted(k for k in used if k not in i18n.M and "." in k and not k.endswith((".", "_")))
    assert not missing, missing
    missing_js = sorted(k for k in js_used if "." not in k and f"js.{k}" not in i18n.M and k not in ("t",))
    assert not missing_js, missing_js


def test_dynamic_key_families_complete():
    from app.scanner import devicetype
    from app.scanner.security import RISKY_PORTS

    for typ in devicetype.TYPES:
        assert f"type.{typ}" in i18n.M
    for _, _, msg in RISKY_PORTS.values():
        for field in ("title", "desc", "fix"):
            assert f"f.{msg}.{field}" in i18n.M
    for kind in ("joined", "joined_maybe_known", "left", "returned", "ip_changed", "port_opened", "port_closed", "finding",
                 "arp_spoof", "rogue_dhcp", "merged", "ip_mac_changed", "archived"):
        assert f"evk.{kind}" in i18n.M
    for job in ("quick", "deep", "dhcp", "weekly_report", "cleanup", "initial"):
        assert f"set.job.{job}" in i18n.M


def test_pick_lang():
    assert i18n.pick_lang("en", "tr-TR", "tr") == "en"
    assert i18n.pick_lang(None, "en-US,en;q=0.9", "tr") == "en"
    assert i18n.pick_lang(None, "de-DE,fr", "en") == "en"
    assert i18n.pick_lang("xx", None, "tr") == "tr"


def test_finding_and_event_rendering():
    params = {"proto": "TCP", "ext": 8443, "client": "192.168.1.20", "iport": 443, "desc": "", "ext_ip": "203.0.113.7"}
    with i18n.use_lang("en"):
        assert i18n.finding_text("wan-forward", params, "title") == "Port exposed to the internet: TCP 8443 → 192.168.1.20:443"
        assert "(no description)" in i18n.finding_text("wan-forward", params, "desc")
        assert "via 203.0.113.7" in i18n.finding_text("wan-forward", params, "desc")
        assert i18n.event_text("joined", {"ip": "10.0.0.5", "mac": "da:00:00:00:00:01", "vendor": None, "random": True}) == \
            "New device: 10.0.0.5 / da:00:00:00:00:01 (Private (random) MAC)"
        assert i18n.event_text("finding", {"msg_id": "telnet", "fparams": {}, "reopened": True}) == "Seen again: Telnet is open"
        # eski (parametresiz) kayıt: kayıtlı Türkçe metin gösterilir
        assert i18n.event_text("joined", "{}", "Yeni cihaz: eski kayıt") == "Yeni cihaz: eski kayıt"
        assert i18n.finding_text(None, None, "title", "Eski başlık") == "Eski başlık"
    with i18n.use_lang("tr"):
        assert i18n.finding_text("telnet", {}, "title") == "Telnet açık"
        assert i18n.event_text("ip_changed", {"old": "1.1.1.1", "new": "1.1.1.2"}) == "IP değişti: 1.1.1.1 → 1.1.1.2"


@pytest.fixture
def seeded(db):
    with Session(db) as s:
        sn = Subnet(cidr="192.168.1.0/24", label="Main")
        s.add(sn)
        s.commit()
        gw = Device(mac="aa:aa:aa:aa:aa:01", ip="192.168.1.1", subnet_id=sn.id, is_gateway=True, device_type="router", vendor="ExampleNet")
        old = Device(mac="da:00:00:00:00:01", ip="192.168.1.30", subnet_id=sn.id, is_random_mac=True, device_type="phone",
                     os_family="apple", online=False)
        new = Device(mac="de:00:00:00:00:02", ip="192.168.1.31", subnet_id=sn.id, is_random_mac=True, device_type="phone", os_family="apple")
        s.add_all([gw, old, new])
        s.commit()
        s.add_all([
            DeviceAlias(device_id=gw.id, mac=gw.mac), DeviceAlias(device_id=old.id, mac=old.mac), DeviceAlias(device_id=new.id, mac=new.mac),
            Port(device_id=gw.id, port=23, service="telnet"),
            Finding(key=f"telnet:{gw.id}:23", device_id=gw.id, severity="high", title="Telnet açık", msg_id="telnet", params="{}", port=23),
            DeviceEvent(device_id=gw.id, kind="joined", message="Yeni cihaz", params=json.dumps({"ip": "192.168.1.1", "mac": gw.mac, "vendor": "ExampleNet"})),
            DeviceEvent(device_id=gw.id, kind="finding", severity="high", message="Telnet açık", params=json.dumps({"msg_id": "telnet", "fparams": {}})),
            MergeSuggestion(device_id=new.id, candidate_id=old.id, score=40, reasons=json.dumps(["dhcp_fp", "timing"])),
            Scan(kind="deep", status="done", snapshot="{}"),
        ])
        s.commit()
    return db


PAGES = ["/", "/devices/1", "/devices/3", "/map", "/security", "/history", "/diff", "/settings", "/report", "/api/report/preview", "/login"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_in_english_have_no_turkish(seeded, path):
    from app.main import app

    with TestClient(app) as c:
        c.cookies.set("lang", "en")
        if path == "/api/report/preview":
            c.put("/api/settings", json={"default_language": "en"})
        r = c.get(path)
        assert r.status_code == 200, r.text[:300]
        assert '<html lang="en">' in r.text
        text = r.text.replace("Türkçe", "")
        leaks = TURKISH_CHARS.findall(text)
        assert not leaks, re.findall(r".{0,40}[çğışöüÇĞİŞÖÜ].{0,40}", text)[:5]


def test_language_switch_and_api_errors(seeded):
    from app.main import app

    with TestClient(app) as c:
        r = c.get("/lang/en?next=/security", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/security" and "lang=en" in r.headers["set-cookie"]
        c.cookies.set("lang", "en")
        assert c.get("/api/devices/999").json()["detail"] == "Device not found"
        assert c.get("/api/findings").json()[0]["title"] == "Telnet is open"
        assert "Possible match" in c.get("/devices/3").text
        c.cookies.set("lang", "tr")
        assert c.get("/api/devices/999").json()["detail"] == "Cihaz bulunamadı"
        assert "Olası eşleşme" in c.get("/devices/3").text
        # dil seçmemiş ziyaretçi: Accept-Language, yoksa varsayılan dil
        c.cookies.clear()
        assert '<html lang="en">' in c.get("/", headers={"Accept-Language": "en-GB"}).text
        c.put("/api/settings", json={"default_language": "en"})
        assert '<html lang="en">' in c.get("/", headers={"Accept-Language": ""}).text
        assert c.put("/api/settings", json={"default_language": "de"}).status_code == 400
