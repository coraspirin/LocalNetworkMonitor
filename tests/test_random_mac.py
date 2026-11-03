"""Gizli (rastgele) MAC'li cihazlar: DHCP parmak izi, rotasyon eşleştirme, öneriler, bildirim ve arşivleme."""

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.models import Device, DeviceAlias, DeviceEvent, DhcpObservation, MergeSuggestion, Subnet, utcnow
from app.pipeline import ScanManager, archive_stale
from app.scanner import dhcpfp
from app.scanner.discovery import SeenHost
from app.scanner.watchdog import dhcp_info_from_packet, parse_dhcp_options

IOS_PRL = [1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]
ANDROID_PRL = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108]


# ------------------------------------------------------------ DHCP ayrıştırma
def test_parse_dhcp_options():
    info = parse_dhcp_options("DA:00:00:00:00:01", [("message-type", 3), ("hostname", b"Aylins-iPhone"),
                                                    ("param_req_list", IOS_PRL), ("client_id", b"\x01\xda\x00\x00\x00\x00\x01"), "end"])
    assert info.mac == "da:00:00:00:00:01" and info.hostname == "Aylins-iPhone"
    assert info.prl == "1,121,3,6,15,108,114,119,252,95,44,46"
    assert info.client_id == "01da0000000001"
    # sunucu mesajları (OFFER=2, ACK=5) yok sayılır
    assert parse_dhcp_options("da:00:00:00:00:01", [("message-type", 2)]) is None


def test_dhcp_info_from_scapy_packet():
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether

    mac = "da:00:00:00:00:07"
    pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
           / BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10)
           / DHCP(options=[("message-type", "request"), ("hostname", "Galaxy-S23"), ("vendor_class_id", "android-dhcp-14"),
                           ("param_req_list", ANDROID_PRL), "end"]))
    info = dhcp_info_from_packet(Ether(bytes(pkt)))
    assert info.mac == mac and info.hostname == "Galaxy-S23" and info.vendor_class == "android-dhcp-14"
    assert dhcpfp.os_family(info.prl, info.vendor_class) == "android"


def test_dhcp_os_family():
    assert dhcpfp.os_family(",".join(map(str, IOS_PRL))) == "apple"
    assert dhcpfp.os_family(",".join(map(str, ANDROID_PRL))) == "android"
    assert dhcpfp.os_family("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "MSFT 5.0") == "windows"
    assert dhcpfp.os_family("1,3,6,15,31,33,43,44,46,47,119,121,249,252") == "windows"
    assert dhcpfp.os_family("1,28,2,3,15,6,119,12,44,47,26,121,42") == "linux"
    assert dhcpfp.os_family("1,3,6,12,15,28,42", "udhcp 1.30.1") == "embedded"
    assert dhcpfp.os_family(None) is None


# ------------------------------------------------------------ pipeline akışı
GW = ("192.168.1.1", "eth0")


@pytest.fixture
def env(db, monkeypatch):
    with Session(db) as s:
        s.add(Subnet(cidr="192.168.1.0/24", label="Ana"))
        s.commit()
    state = {"hosts": [], "mdns": {}, "notified": []}
    monkeypatch.setattr("app.pipeline.discovery.sweep", lambda cidr, mode: (list(state["hosts"]), "arp"))
    monkeypatch.setattr("app.pipeline.discovery.reverse_dns", lambda ips: {})
    monkeypatch.setattr("app.pipeline.services.mdns_browse", lambda timeout=5.0: dict(state["mdns"]))
    monkeypatch.setattr("app.pipeline.default_gateway", lambda: GW)
    monkeypatch.setattr("app.notify.send_batch", lambda items: state["notified"].extend(items))
    return db, state


def _dhcp(engine, mac, prl, hostname=None):
    from app.monitor import record_dhcp
    from app.scanner.watchdog import DhcpInfo

    record_dhcp(DhcpInfo(mac=mac, hostname=hostname, prl=",".join(map(str, prl))))


def test_nameless_iphone_rotation_suggests_and_defers_notification(env):
    db, state = env
    m = ScanManager()
    gw = SeenHost("192.168.1.1", "aa:aa:aa:aa:aa:01")
    android = SeenHost("192.168.1.50", "d2:00:00:00:00:50")

    # 1) iPhone (isimsiz, gizli MAC) ve bir Android telefon ağda
    _dhcp(db, "da:00:00:00:00:01", IOS_PRL)
    _dhcp(db, "d2:00:00:00:00:50", ANDROID_PRL)
    state["hosts"] = [gw, SeenHost("192.168.1.30", "da:00:00:00:00:01"), android]
    m.run_quick()
    state["notified"].clear()
    m.run_quick()  # ertelenen bildirimler gönderilir
    with Session(db) as s:
        iphone = s.exec(select(Device).where(Device.mac == "da:00:00:00:00:01")).one()
        assert iphone.os_family == "apple" and iphone.device_type == "phone"
        assert iphone.dhcp_fp.startswith("1,121,3,6")
        iphone.trusted = True  # kullanıcı tanıdı
        s.add(iphone)
        s.commit()
        iphone_id = iphone.id

    # 2) iPhone MAC'ini değiştirir: eski adres kaybolur, yeni adres hemen gelir (ağı unut/yeniden bağlan)
    _dhcp(db, "de:00:00:00:00:02", IOS_PRL)
    state["hosts"] = [gw, android, SeenHost("192.168.1.31", "de:00:00:00:00:02")]
    state["notified"].clear()
    m.run_quick()
    with Session(db) as s:
        new = s.exec(select(Device).where(Device.mac == "de:00:00:00:00:02")).one()
        assert new.id != iphone_id  # isim yok -> otomatik birleştirme yok
        assert new.notify_pending  # akıllı mod: bildirim ertelendi
        sg = s.exec(select(MergeSuggestion).where(MergeSuggestion.device_id == new.id)).one()
        assert sg.candidate_id == iphone_id and sg.status == "pending"
        assert {"dhcp_fp", "os_family", "timing"} <= set(json.loads(sg.reasons))
        # Android adayı farklı OS olduğu için önerilmez
        assert s.exec(select(MergeSuggestion).where(MergeSuggestion.candidate_id != iphone_id)).first() is None
        ev = s.exec(select(DeviceEvent).where(DeviceEvent.device_id == new.id, DeviceEvent.kind == "joined_maybe_known")).one()
        assert json.loads(ev.params)["score"] == sg.score
        new_id, sg_id = new.id, sg.id
    assert state["notified"] == []  # henüz bildirim yok

    # 3) bir sonraki taramada ertelenmiş karar: "muhtemelen bilinen cihaz" (düşük önem) bildirimi
    m.run_quick()
    assert len(state["notified"]) == 1
    title, text, sev = state["notified"][0]
    assert sev == "low" and "da:00" not in text and "de:00:00:00:00:02" in text

    # 4) kullanıcı öneriyi kabul eder -> tek cihaz, iki MAC, güvenilir işareti korunur
    from app.main import app

    with TestClient(app) as c:
        r = c.post(f"/api/suggestions/{sg_id}/accept")
        assert r.status_code == 200 and r.json()["id"] == iphone_id
    with Session(db) as s:
        assert s.get(Device, new_id) is None
        d = s.get(Device, iphone_id)
        assert d.trusted and d.mac == "de:00:00:00:00:02" and d.online
        assert {a.mac for a in s.exec(select(DeviceAlias).where(DeviceAlias.device_id == iphone_id))} == {"da:00:00:00:00:01", "de:00:00:00:00:02"}


def test_named_rotation_auto_merges_silently(env):
    db, state = env
    m = ScanManager()
    _dhcp(db, "da:00:00:00:00:01", IOS_PRL, hostname="Aylins-iPhone")
    state["hosts"] = [SeenHost("192.168.1.30", "da:00:00:00:00:01")]
    m.run_quick()
    m.run_quick()
    state["notified"].clear()
    _dhcp(db, "de:00:00:00:00:02", IOS_PRL, hostname="Aylins-iPhone")
    state["hosts"] = [SeenHost("192.168.1.31", "de:00:00:00:00:02")]
    m.run_quick()
    m.run_quick()
    with Session(db) as s:
        assert len(s.exec(select(Device)).all()) == 1
        ev = s.exec(select(DeviceEvent).where(DeviceEvent.kind == "merged")).one()
        assert json.loads(ev.params)["auto"] is True
    assert state["notified"] == []


def test_rejected_suggestion_is_not_repeated(env):
    db, state = env
    m = ScanManager()
    _dhcp(db, "da:00:00:00:00:01", IOS_PRL)
    state["hosts"] = [SeenHost("192.168.1.30", "da:00:00:00:00:01")]
    m.run_quick()
    _dhcp(db, "de:00:00:00:00:02", IOS_PRL)
    state["hosts"] = [SeenHost("192.168.1.31", "de:00:00:00:00:02")]
    m.run_quick()
    from app.main import app

    with Session(db) as s:
        sg = s.exec(select(MergeSuggestion)).one()
    with TestClient(app) as c:
        assert c.post(f"/api/suggestions/{sg.id}/reject").status_code == 200
        assert c.post(f"/api/suggestions/{sg.id}/reject").status_code == 404
    m.run_quick()  # yeniden puanlama
    with Session(db) as s:
        rows = s.exec(select(MergeSuggestion)).all()
        assert len(rows) == 1 and rows[0].status == "rejected"


@pytest.mark.parametrize("mode,expected", [("always", 1), ("never", 0)])
def test_random_notify_modes(env, mode, expected):
    from app import settings_store

    db, state = env
    settings_store.update({"random_mac_notify": mode})
    state["hosts"] = [SeenHost("192.168.1.30", "da:00:00:00:00:01")]
    ScanManager().run_quick()
    assert len(state["notified"]) == expected


def test_archive_stale_random_devices(db):
    old = utcnow() - timedelta(days=40)
    with Session(db) as s:
        s.add_all([
            Device(mac="da:00:00:00:00:01", is_random_mac=True, last_seen=old, online=False),
            Device(mac="da:00:00:00:00:02", is_random_mac=True, last_seen=old, online=False, name="Annemin telefonu"),
            Device(mac="b8:27:eb:00:00:01", is_random_mac=False, last_seen=old, online=False),
            Device(mac="da:00:00:00:00:03", is_random_mac=True, last_seen=utcnow(), online=True),
        ])
        s.commit()
        assert archive_stale(s) == 1
        s.commit()
        archived = s.exec(select(Device).where(Device.archived == True)).all()  # noqa: E712
        assert [d.mac for d in archived] == ["da:00:00:00:00:01"]


def test_migration_adds_new_columns(tmp_path):
    """Önceki sürümün veritabanı (yeni sütunlar olmadan) açılınca otomatik geçiş."""
    import sqlite3

    from sqlmodel import create_engine

    from app import db as dbmod

    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE device (id INTEGER PRIMARY KEY, mac VARCHAR, ip VARCHAR, device_type VARCHAR NOT NULL DEFAULT 'unknown',
            is_random_mac BOOLEAN NOT NULL DEFAULT 0, trusted BOOLEAN NOT NULL DEFAULT 0, online BOOLEAN NOT NULL DEFAULT 1,
            mdns_services VARCHAR NOT NULL DEFAULT '[]', ssdp_info VARCHAR NOT NULL DEFAULT '{}', is_gateway BOOLEAN NOT NULL DEFAULT 0,
            missed_scans INTEGER NOT NULL DEFAULT 0, first_seen DATETIME, last_seen DATETIME, subnet_id INTEGER, name VARCHAR,
            location VARCHAR, owner VARCHAR, notes VARCHAR, hostname VARCHAR, vendor VARCHAR, os_guess VARCHAR, mdns_name VARCHAR,
            netbios_name VARCHAR, last_rtt_ms FLOAT, last_deep_scan DATETIME);
        INSERT INTO device (id, mac, ip, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:ff', '10.0.0.2', '2026-11-01 10:00:00', '2026-11-01 10:00:00');
        CREATE TABLE deviceevent (id INTEGER PRIMARY KEY, device_id INTEGER, ts DATETIME, kind VARCHAR NOT NULL,
            severity VARCHAR NOT NULL DEFAULT 'info', message VARCHAR NOT NULL DEFAULT '');
        INSERT INTO deviceevent (device_id, ts, kind, message) VALUES (1, '2026-11-01 10:00:00', 'joined', 'Yeni cihaz: 10.0.0.2');
    """)
    con.commit()
    con.close()

    engine = create_engine(f"sqlite:///{path}")
    dbmod.set_engine(engine)
    try:
        dbmod.init_db()
        added = dbmod.migrate(engine)
        assert added == []  # ikinci çalıştırmada eklenecek bir şey kalmaz
        with Session(engine) as s:
            d = s.get(Device, 1)
            assert d.archived is False and d.notify_pending is False and d.dhcp_hostname is None
            e = s.exec(select(DeviceEvent)).one()
            assert e.params == "{}"
            s.add(DhcpObservation(mac="aa:bb:cc:dd:ee:ff", prl="1,3,6"))
            s.commit()
    finally:
        dbmod.set_engine(None)
