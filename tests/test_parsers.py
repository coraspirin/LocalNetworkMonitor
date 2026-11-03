from datetime import datetime

from app.netutil import connected_subnets, default_gateway, is_random_mac, normalize_mac
from app.scanner import devicetype, nmapxml, vendor
from app.scanner.security import analyze_host
from app.scanner.services import parse_device_description, parse_ssdp_response


def test_nmap_xml_parse(fixture_text):
    hosts = nmapxml.parse(fixture_text("nmap_host.xml"))
    assert len(hosts) == 2
    h = hosts[0]
    assert h.ip == "192.168.1.20"
    assert h.mac == "b8:27:eb:12:34:56"
    assert h.vendor == "Raspberry Pi Foundation"
    assert h.hostname == "nas.lan"
    assert h.os_guess == "Linux 4.15 - 5.8" and h.os_accuracy == 95
    assert h.os_class["osfamily"] == "Linux"
    assert h.rtt_ms == 1.52
    assert [p.port for p in h.open_ports] == [21, 23, 443, 445, 8080]
    ftp = h.ports[0]
    assert ftp.product == "vsftpd" and ftp.version == "2.3.4"
    assert {r["id"] for r in ftp.script_tables["vulners"]} == {"CVE-2011-2523", "EDB-ID:49757"}
    assert nmapxml.netbios_name(h) == "NAS01"
    assert hosts[1].status == "down"


def test_nmap_xml_empty():
    assert nmapxml.parse("") == []


def test_security_rules(fixture_text):
    host = nmapxml.parse(fixture_text("nmap_host.xml"))[0]
    findings = analyze_host(host, now=datetime(2024, 6, 1))
    by_rule = {f.rule: f for f in findings}
    assert by_rule["ftp-anon"].severity == "high"
    assert by_rule["ftp"].severity == "medium"
    assert by_rule["telnet"].severity == "high"
    assert by_rule["smbv1"].severity == "high"
    assert by_rule["default-creds"].severity == "critical"
    assert by_rule["tls-expired"].port == 443
    assert "tls-selfsigned" in by_rule
    v = by_rule["vulners"]
    assert v.severity == "critical"
    assert v.cves[0]["cvss"] == 10.0 and v.cves[0]["exploit"] is True
    # gateway olmayan cihazda router kuralı çalışmaz
    assert "router-http" not in by_rule


def test_router_http_rule():
    host = nmapxml.HostResult(ip="192.168.1.1", ports=[nmapxml.PortResult(80, "tcp", "open", service="http")])
    rules = {f.rule for f in analyze_host(host, is_gateway=True)}
    assert "router-http" in rules
    host.ports.append(nmapxml.PortResult(443, "tcp", "open", service="https", tunnel="ssl"))
    assert "router-http" not in {f.rule for f in analyze_host(host, is_gateway=True)}


def test_mac_helpers():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("nonsense") is None
    assert is_random_mac("da:a1:19:00:00:01")  # 0xda -> locally administered
    assert not is_random_mac("b8:27:eb:12:34:56")
    assert not is_random_mac("03:00:00:00:00:00")  # multicast


def test_vendor_lookup():
    if not vendor._table():
        import pytest

        pytest.skip("nmap-mac-prefixes yok")
    assert "Raspberry" in (vendor.lookup("b8:27:eb:00:00:01") or "")
    assert vendor.lookup("da:a1:19:00:00:01") is None


def test_routes(tmp_path):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    )
    assert default_gateway(route) == ("192.168.1.1", "eth0")
    assert connected_subnets(route) == [("192.168.1.0/24", "eth0")]


def test_ssdp_parsing(fixture_text):
    r = parse_ssdp_response(
        b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: Linux UPnP/1.1 MiniUPnPd/2.2\r\n\r\n",
        "192.168.1.1",
    )
    assert r.location == "http://192.168.1.1:5000/rootDesc.xml"
    assert "InternetGatewayDevice" in r.st
    desc = parse_device_description(fixture_text("igd_desc.xml"))
    assert desc["friendlyName"] == "Ev Router"
    assert desc["modelName"] == "XR-500"


def test_device_classification():
    assert devicetype.classify(is_gateway=True) == "router"
    assert devicetype.classify(ports={9100, 80}) == "printer"
    assert devicetype.classify(mdns_services=[{"type": "_googlecast._tcp"}]) == "tv"
    assert devicetype.classify(hostname="Johns-iPhone") == "phone"
    assert devicetype.classify(vendor="Espressif Inc.") == "iot"
    assert devicetype.classify(vendor="Synology Incorporated", ports={5000, 5001, 445}) == "nas"
    assert devicetype.classify(os_guess="Microsoft Windows 10") == "computer"
    assert devicetype.classify() == "unknown"
