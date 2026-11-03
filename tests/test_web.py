"""Web arayüzü ve API uç noktaları."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.models import Device, DeviceAlias, Finding, Port, Subnet


@pytest.fixture
def client(db, monkeypatch):
    from app.main import app

    with Session(db) as s:
        sn = Subnet(cidr="192.168.1.0/24", label="Ana")
        s.add(sn)
        s.commit()
        gw = Device(mac="aa:aa:aa:aa:aa:01", ip="192.168.1.1", subnet_id=sn.id, is_gateway=True, device_type="router", vendor="ExampleNet")
        nas = Device(mac="b8:27:eb:12:34:56", ip="192.168.1.20", subnet_id=sn.id, hostname="nas.lan", device_type="nas")
        s.add_all([gw, nas])
        s.commit()
        s.add_all([
            DeviceAlias(device_id=gw.id, mac=gw.mac), DeviceAlias(device_id=nas.id, mac=nas.mac),
            Port(device_id=nas.id, port=23, service="telnet"),
            Finding(key=f"telnet:{nas.id}:23", device_id=nas.id, severity="high", title="Telnet açık", port=23),
        ])
        s.commit()
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("path", ["/", "/devices/2", "/map", "/security", "/history", "/diff", "/settings", "/report", "/api/report/preview"])
def test_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.text[:500]


def test_device_api_and_exports(client):
    devices = client.get("/api/devices").json()
    assert [d["ip"] for d in devices] == ["192.168.1.1", "192.168.1.20"]
    nas = devices[1]
    assert nas["worst_severity"] == "high" and nas["open_ports"] == 1
    assert client.get("/api/devices", params={"q": "nas"}).json()[0]["id"] == nas["id"]

    r = client.patch(f"/api/devices/{nas['id']}", json={"name": "Depo", "trusted": True, "location": "Çalışma odası"})
    assert r.status_code == 200 and r.json()["name"] == "Depo" and r.json()["trusted"]
    assert client.patch(f"/api/devices/{nas['id']}", json={"device_type": "toaster"}).status_code == 400

    csv = client.get("/api/export/devices.csv")
    assert "Depo" in csv.text and csv.headers["content-type"].startswith("text/csv")
    js = client.get("/api/export/devices.json").json()
    assert js[1]["ports"][0]["port"] == 23

    m = client.get("/api/map").json()
    assert m["gateway"]["ip"] == "192.168.1.1" and len(m["devices"]) == 2


def test_score_and_finding_ignore(client):
    assert client.get("/api/score").json()["score"] == 90
    fid = client.get("/api/findings").json()[0]["id"]
    client.post(f"/api/findings/{fid}/ignore", json={"ignored": True})
    assert client.get("/api/score").json()["score"] == 100


def test_settings_and_subnets(client):
    r = client.put("/api/settings", json={"quick_interval_min": 10, "enable_vulners": False, "unknown_key": 1})
    assert r.status_code == 200 and r.json()["quick_interval_min"] == 10 and r.json()["enable_vulners"] is False
    assert client.put("/api/settings", json={"top_ports": "abc"}).status_code == 400

    assert client.post("/api/subnets", json={"cidr": "10.20.0.0/24", "label": "IoT"}).status_code == 200
    assert client.post("/api/subnets", json={"cidr": "10.20.0.0/24", "label": "IoT"}).status_code == 409
    assert client.post("/api/subnets", json={"cidr": "10.0.0.0/8", "label": "çok büyük"}).status_code == 400
    assert client.post("/api/subnets", json={"cidr": "nope", "label": "x"}).status_code == 400
    assert len(client.get("/api/subnets").json()) == 2


def test_test_notification_requires_urls(client):
    assert client.post("/api/settings/test-notification", json={"urls": ""}).status_code == 400


def test_auth(db, monkeypatch):
    from app.config import get_settings
    from app.main import app

    monkeypatch.setattr(get_settings(), "admin_password", "gizli")
    with TestClient(app) as c:
        assert c.get("/api/devices").status_code == 401
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
        assert c.get("/api/health").status_code == 200
        assert c.post("/login", data={"password": "yanlis", "next": "/"}).status_code == 401
        r = c.post("/login", data={"password": "gizli", "next": "/"}, follow_redirects=False)
        assert r.status_code == 303
        assert c.get("/api/devices").status_code == 200
