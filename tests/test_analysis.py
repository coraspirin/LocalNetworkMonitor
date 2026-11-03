from app.scanner.analysis import Identity, diff_snapshots, find_identity_match, score_grade, security_score
from app.scanner.watchdog import ArpDetector, evaluate_dhcp_offers


# ------------------------------------------------------------ MAC birleştirme
def test_random_mac_matches_by_mdns_name():
    existing = [
        Identity(1, hostname="laptop.lan"),
        Identity(2, mdns_name="Aylins-iPhone", is_random_mac=True),
    ]
    cand = Identity(10, mdns_name="aylins-iphone.local", is_random_mac=True)
    assert find_identity_match(cand, existing) == 2


def test_random_mac_matches_by_hostname_across_fields():
    existing = [Identity(3, mdns_name="galaxy-s23")]
    assert find_identity_match(Identity(11, hostname="Galaxy-S23.lan", is_random_mac=True), existing) == 3


def test_no_match_for_hardware_mac_or_generic_names():
    existing = [Identity(1, hostname="android"), Identity(2, hostname="tv")]
    assert find_identity_match(Identity(9, hostname="tv"), existing) is None  # donanım MAC'i
    assert find_identity_match(Identity(9, hostname="android", is_random_mac=True), existing) is None


def test_ambiguous_match_is_skipped():
    existing = [Identity(1, hostname="phone"), Identity(2, mdns_name="phone")]
    assert find_identity_match(Identity(9, hostname="phone", is_random_mac=True), existing) is None


def test_port_signature_match_only_between_random_macs():
    sig = frozenset({62078, 49152})
    existing = [Identity(1, port_signature=sig), Identity(2, port_signature=sig, is_random_mac=True)]
    assert find_identity_match(Identity(9, port_signature=sig, is_random_mac=True), existing) == 2
    assert find_identity_match(Identity(9, port_signature=frozenset({62078}), is_random_mac=True), existing) is None


# ------------------------------------------------------------ diff
def test_diff_snapshots():
    prev = {
        "1": {"name": "NAS", "ip": "10.0.0.2", "os": "Linux 4", "ports": {"tcp/22": "ssh OpenSSH 8.0", "tcp/80": "http"}, "findings": {"a": {"title": "Telnet", "severity": "high"}}},
        "2": {"name": "TV", "ip": "10.0.0.3", "os": None, "ports": {}, "findings": {}},
    }
    cur = {
        "1": {"name": "NAS", "ip": "10.0.0.5", "os": "Linux 5", "ports": {"tcp/22": "ssh OpenSSH 9.6", "tcp/443": "https"}, "findings": {"b": {"title": "SMBv1", "severity": "high"}}},
        "3": {"name": "Yeni", "ip": "10.0.0.9", "os": None, "ports": {"tcp/23": "telnet"}, "findings": {}},
    }
    kinds = {(c["device"], c["kind"]) for c in diff_snapshots(prev, cur)}
    assert ("1", "port_opened") in kinds and ("1", "port_closed") in kinds
    assert ("1", "service_changed") in kinds and ("1", "os_changed") in kinds and ("1", "ip_changed") in kinds
    assert ("1", "finding_new") in kinds and ("1", "finding_resolved") in kinds
    assert ("2", "device_missing") in kinds
    assert ("3", "device_added") in kinds and ("3", "port_opened") in kinds
    assert diff_snapshots(cur, cur) == []


# ------------------------------------------------------------ skor
def test_security_score():
    assert security_score([]) == 100
    assert security_score([(1, "high"), (1, "medium"), (2, "low")]) == 85
    # cihaz başına tavan: 3 kritik = 75 ama en fazla 40 düşer
    assert security_score([(1, "critical")] * 3) == 60
    assert security_score([(i, "critical") for i in range(10)]) == 0
    assert score_grade(95)[0] == "A" and score_grade(10)[0] == "F"


# ------------------------------------------------------------ ARP / DHCP
def test_arp_detector_gateway_spoof():
    det = ArpDetector(gateway_ip="192.168.1.1", gateway_mac="aa:aa:aa:aa:aa:01")
    assert det.observe("192.168.1.1", "aa:aa:aa:aa:aa:01", now=0) == []
    alerts = det.observe("192.168.1.1", "de:ad:be:ef:00:01", now=1)
    assert len(alerts) == 1 and alerts[0].kind == "arp_spoof" and alerts[0].severity == "critical"
    # bekleme süresi içinde tekrar uyarı yok
    assert det.observe("192.168.1.1", "de:ad:be:ef:00:01", now=60) == []
    assert len(det.observe("192.168.1.1", "de:ad:be:ef:00:01", now=4000)) == 1
    # kullanıcı yeni MAC'i onaylarsa uyarı kesilir
    det.accept_gateway_mac("de:ad:be:ef:00:01")
    assert det.observe("192.168.1.1", "de:ad:be:ef:00:01", now=9000) == []


def test_arp_detector_learns_gateway_and_tracks_changes():
    det = ArpDetector(gateway_ip="192.168.1.1")
    assert det.observe("192.168.1.1", "aa:aa:aa:aa:aa:01", now=0) == []
    assert det.gateway_mac == "aa:aa:aa:aa:aa:01"
    det.observe("192.168.1.50", "11:11:11:11:11:11", now=0)
    alerts = det.observe("192.168.1.50", "22:22:22:22:22:22", now=1)
    assert alerts[0].kind == "ip_mac_changed" and alerts[0].severity == "info"


def test_dhcp_evaluation():
    one = [{"server_id": "192.168.1.1"}]
    assert evaluate_dhcp_offers(one, "192.168.1.1") == []
    assert evaluate_dhcp_offers([], "192.168.1.1") == []
    two = one + [{"server_id": "192.168.1.66"}]
    assert evaluate_dhcp_offers(two, "192.168.1.1")[0].kind == "rogue_dhcp"
    wrong = [{"server_id": "10.0.0.1"}]
    assert "Beklenmeyen" in evaluate_dhcp_offers(wrong, "192.168.1.1")[0].message
