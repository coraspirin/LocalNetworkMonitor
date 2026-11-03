"""Tarama hattı: keşif sonuçlarının veritabanına işlenmesi (ağ erişimi taklit edilir)."""

from sqlmodel import Session, select

from app.models import Device, DeviceAlias, DeviceEvent, Finding, PresenceSample, Scan, ScanDiff, Subnet
from app.pipeline import ScanManager, merge_devices, split_alias
from app.scanner import nmapxml
from app.scanner.discovery import SeenHost

GW = ("192.168.1.1", "eth0")


def _setup(monkeypatch, hosts_ref, mdns_ref=None, rdns_ref=None):
    monkeypatch.setattr("app.pipeline.discovery.sweep", lambda cidr, mode: (list(hosts_ref), "arp"))
    monkeypatch.setattr("app.pipeline.discovery.reverse_dns", lambda ips: dict(rdns_ref or {}))
    monkeypatch.setattr("app.pipeline.services.mdns_browse", lambda timeout=5.0: dict(mdns_ref or {}))
    monkeypatch.setattr("app.pipeline.default_gateway", lambda: GW)


def _add_subnet(engine):
    with Session(engine) as s:
        s.add(Subnet(cidr="192.168.1.0/24", label="Ana"))
        s.commit()


def test_quick_scan_new_devices_and_offline(db, monkeypatch):
    _add_subnet(db)
    hosts = [SeenHost("192.168.1.1", "aa:aa:aa:aa:aa:01", 0.8), SeenHost("192.168.1.20", "b8:27:eb:12:34:56", 2.0)]
    _setup(monkeypatch, hosts, rdns_ref={"192.168.1.20": "nas.lan"})
    m = ScanManager()
    m.run_quick()

    with Session(db) as s:
        devs = {d.ip: d for d in s.exec(select(Device))}
        assert devs["192.168.1.1"].is_gateway and devs["192.168.1.1"].device_type == "router"
        assert devs["192.168.1.20"].hostname == "nas.lan"
        assert "Raspberry" in (devs["192.168.1.20"].vendor or "Raspberry")
        assert len(s.exec(select(DeviceEvent).where(DeviceEvent.kind == "joined")).all()) == 2
        assert len(s.exec(select(DeviceAlias)).all()) == 2

    # NAS kaybolur: 3 kaçırılan taramadan sonra çevrimdışı
    hosts.pop()
    for _ in range(3):
        m.run_quick()
    with Session(db) as s:
        nas = s.exec(select(Device).where(Device.ip == "192.168.1.20")).one()
        assert not nas.online and nas.missed_scans == 3
        assert s.exec(select(DeviceEvent).where(DeviceEvent.kind == "left")).first() is not None
        assert len(s.exec(select(PresenceSample).where(PresenceSample.device_id == nas.id)).all()) == 4

    # geri döner (IP değişmiş)
    hosts.append(SeenHost("192.168.1.21", "b8:27:eb:12:34:56", 2.0))
    m.run_quick()
    with Session(db) as s:
        nas = s.exec(select(Device).where(Device.mac == "b8:27:eb:12:34:56")).one()
        assert nas.online and nas.ip == "192.168.1.21"
        kinds = {e.kind for e in s.exec(select(DeviceEvent).where(DeviceEvent.device_id == nas.id))}
        assert {"returned", "ip_changed"} <= kinds


def test_random_mac_rotation_is_merged(db, monkeypatch):
    _add_subnet(db)
    hosts = [SeenHost("192.168.1.40", "da:00:00:00:00:01")]
    mdns = {"192.168.1.40": {"name": "Aylins-iPhone", "services": []}}
    _setup(monkeypatch, hosts, mdns_ref=mdns)
    m = ScanManager()
    m.run_quick()

    # telefon yeni bir gizli MAC ile geri gelir
    hosts[0] = SeenHost("192.168.1.41", "de:00:00:00:00:02")
    mdns.clear()
    mdns["192.168.1.41"] = {"name": "Aylins-iPhone", "services": []}
    m.run_quick()

    with Session(db) as s:
        devs = s.exec(select(Device)).all()
        assert len(devs) == 1
        d = devs[0]
        assert d.mac == "de:00:00:00:00:02" and d.is_random_mac
        assert {a.mac for a in s.exec(select(DeviceAlias))} == {"da:00:00:00:00:01", "de:00:00:00:00:02"}
        kinds = [e.kind for e in s.exec(select(DeviceEvent))]
        assert kinds.count("joined") == 1 and "merged" in kinds

        # elle ayırma
        alias = s.exec(select(DeviceAlias).where(DeviceAlias.mac == "da:00:00:00:00:01")).one()
        new = split_alias(s, alias.id)
        s.commit()
        assert new.mac == "da:00:00:00:00:01"
        # ve tekrar birleştirme
        merge_devices(s, new.id, d.id)
        s.commit()
        assert len(s.exec(select(Device)).all()) == 1


def test_deep_scan_findings_diff_and_score(db, monkeypatch, fixture_text):
    _add_subnet(db)
    hosts = [SeenHost("192.168.1.20", "b8:27:eb:12:34:56")]
    _setup(monkeypatch, hosts)
    monkeypatch.setattr("app.pipeline.services.ssdp_discover", lambda: {})
    monkeypatch.setattr("app.pipeline.router.audit", lambda devs: __import__("app.scanner.router", fromlist=["RouterAudit"]).RouterAudit())
    host_xml = fixture_text("nmap_host.xml")
    state = {"xml": host_xml}
    monkeypatch.setattr("app.pipeline.ports.scan_host", lambda ip, *a, **k: nmapxml.parse(state["xml"])[0])

    m = ScanManager()
    first = m.run_deep()
    with Session(db) as s:
        d = s.exec(select(Device)).one()
        assert d.netbios_name == "NAS01" and d.os_guess.startswith("Linux 4.15")
        open_f = s.exec(select(Finding).where(Finding.resolved == False)).all()  # noqa: E712
        assert {"ftp-anon", "telnet", "smbv1", "default-creds", "vulners"} <= {f.key.split(":")[0] for f in open_f}
        assert s.get(Scan, first).status == "done"

    # ikinci tarama: telnet kapatılmış
    state["xml"] = host_xml.replace('portid="23">\n      <state state="open"', 'portid="23">\n      <state state="closed"')
    second = m.run_deep()
    with Session(db) as s:
        telnet = s.exec(select(Finding).where(Finding.key.startswith("telnet:"))).one()
        assert telnet.resolved
        diff = s.exec(select(ScanDiff).where(ScanDiff.scan_id == second)).one()
        assert diff.prev_scan_id == first
        assert '"port_closed"' in diff.changes and '"finding_resolved"' in diff.changes
