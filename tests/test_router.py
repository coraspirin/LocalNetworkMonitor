"""UPnP IGD denetimi: sahte bir IGD HTTP sunucusuna karşı uçtan uca test."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.scanner import router
from app.scanner.services import SsdpDevice

MAPPINGS = [
    ("", "8443", "TCP", "443", "192.168.1.20", "1", "NAS web"),
    ("", "3389", "TCP", "3389", "192.168.1.30", "1", "Remote desktop"),
]


def _soap_ok(action: str, fields: dict) -> bytes:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        f'<u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{inner}</u:{action}Response>'
        "</s:Body></s:Envelope>"
    ).encode()


FAULT = (
    b'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>'
    b"<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring></s:Fault></s:Body></s:Envelope>"
)


@pytest.fixture
def igd_server(fixture_text):
    desc = fixture_text("igd_desc.xml").encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(desc)

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            action = self.headers["SOAPAction"].strip('"').split("#")[1]
            if action == "GetExternalIPAddress":
                payload, code = _soap_ok(action, {"NewExternalIPAddress": "203.0.113.7"}), 200
            else:
                idx = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
                if idx < len(MAPPINGS):
                    keys = ["NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort", "NewInternalClient", "NewEnabled", "NewPortMappingDescription"]
                    payload, code = _soap_ok(action, dict(zip(keys, MAPPINGS[idx]))), 200
                else:
                    payload, code = FAULT, 500
            self.send_response(code)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(payload)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/rootDesc.xml"
    srv.shutdown()


def test_find_wan_service(fixture_text):
    st, url = router.find_wan_service(fixture_text("igd_desc.xml"), "http://192.168.1.1:5000/rootDesc.xml")
    assert st.endswith("WANIPConnection:1")
    assert url == "http://192.168.1.1:5000/ctl/IPConn"


def test_audit_against_fake_igd(igd_server):
    dev = SsdpDevice(ip="127.0.0.1", locations=[igd_server], sts=["urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
                     description={"deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "manufacturer": "ExampleNet",
                                  "modelName": "XR-500", "location": igd_server})
    audit = router.audit({"127.0.0.1": dev})
    assert audit.igd_found and audit.model == "ExampleNet XR-500"
    assert audit.external_ip == "203.0.113.7"
    assert [(m.external_port, m.internal_client) for m in audit.mappings] == [(8443, "192.168.1.20"), (3389, "192.168.1.30")]

    findings = router.audit_findings(audit)
    rules = {f.key_rule: (f.severity, ip) for f, ip in findings}
    assert rules["upnp-enabled"][0] == "medium"
    assert rules["wan-forward-tcp-3389"] == ("high", "192.168.1.30")  # riskli iç port
    assert rules["wan-forward-tcp-8443"] == ("medium", "192.168.1.20")


def test_audit_without_igd():
    audit = router.audit({})
    assert not audit.igd_found
    assert router.audit_findings(audit) == []
