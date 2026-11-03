"""Cihaz tipi tahmini: üretici, açık portlar, mDNS servisleri, SSDP ve işletim sistemi bilgisinden."""

from __future__ import annotations

# tip -> simge (etiketler i18n kataloğunda: type.<tip>)
TYPES = {
    "router": "🌐",
    "phone": "📱",
    "computer": "💻",
    "printer": "🖨️",
    "tv": "📺",
    "speaker": "🔊",
    "camera": "📷",
    "nas": "🗄️",
    "gaming": "🎮",
    "iot": "🔌",
    "unknown": "❔",
}

VENDOR_HINTS = [
    (("synology", "qnap", "western digital", "asustor", "terramaster"), "nas"),
    (("hikvision", "dahua", "axis comm", "reolink", "wyze", "arlo", "ezviz", "foscam", "amcrest"), "camera"),
    (("sonos", "bose", "harman", "denon", "bang & olufsen"), "speaker"),
    (("nintendo", "sony interactive", "microsoft xbox", "valve"), "gaming"),
    (("roku", "lg electronics", "vizio", "tcl", "hisense", "philips tv", "vestel", "arcelik", "beko"), "tv"),
    (("brother", "canon", "epson", "lexmark", "kyocera", "ricoh", "xerox", "hewlett packard printer"), "printer"),
    (("espressif", "tuya", "shelly", "sonoff", "itead", "xiaomi", "yeelight", "philips lighting", "signify", "ring", "nest", "ecobee", "tp-link smart", "broadlink", "tasmota", "lifx", "meross", "aqara", "lumi united"), "iot"),
    (("ubiquiti", "mikrotik", "netgear", "tp-link", "zyxel", "huawei", "zte", "avm", "airties", "linksys", "d-link", "cisco", "juniper", "aruba", "fritz", "keenetic", "tenda", "asus"), "router"),
    (("raspberry pi",), "computer"),
    (("intel", "dell", "lenovo", "micro-star", "gigabyte", "asrock", "realtek", "hewlett packard", "acer"), "computer"),
    (("oneplus", "oppo", "vivo", "motorola", "google", "samsung", "apple", "xiaomi communications", "huawei device"), "phone"),
]

MDNS_HINTS = [
    (("_ipp", "_printer", "_pdl-datastream", "_ipps", "_scanner"), "printer"),
    (("_googlecast", "_airplay", "_raop", "_androidtvremote", "_roku", "_mediaremotetv"), "tv"),
    (("_spotify-connect", "_sonos"), "speaker"),
    (("_hap", "_homekit", "_hue", "_esphomelib", "_matter", "_matterc", "_shelly"), "iot"),
    (("_smb", "_afpovertcp", "_nfs", "_adisk"), "nas"),
    (("_apple-mobdev2", "_companion-link"), "phone"),
    (("_device-info", "_rdlink", "_ssh", "_sftp-ssh", "_workstation"), "computer"),
]


def _match(text: str, table) -> str | None:
    text = text.lower()
    for keys, typ in table:
        if any(k in text for k in keys):
            return typ
    return None


def classify(
    vendor: str | None = None,
    os_guess: str | None = None,
    os_type: str | None = None,
    ports: set[int] | None = None,
    mdns_services: list[dict] | None = None,
    ssdp: dict | None = None,
    hostname: str | None = None,
    is_gateway: bool = False,
    os_family: str | None = None,
    is_random_mac: bool = False,
) -> str:
    if is_gateway:
        return "router"
    ports = ports or set()
    mdns_types = " ".join(s.get("type", "") for s in (mdns_services or []))
    ssdp = ssdp or {}
    host = (hostname or "").lower()

    # 1) güçlü sinyaller: mDNS ve SSDP cihaz tipi
    t = _match(mdns_types, MDNS_HINTS)
    if t in ("printer", "tv", "speaker", "iot"):
        return t
    st = (ssdp.get("deviceType", "") + " " + ssdp.get("modelName", "")).lower()
    if "mediarenderer" in st or "dial" in st:
        return "tv"
    if "printer" in st:
        return "printer"
    if "internetgatewaydevice" in st:
        return "router"

    # 2) port imzaları
    if {9100, 631} & ports or {515} & ports:
        return "printer"
    if 554 in ports and not ({22, 445} & ports):
        return "camera"
    if {8008, 8009} <= ports or 7000 in ports and 49152 in ports:
        return "tv"
    if {5000, 5001} <= ports and 445 in ports:
        return "nas"

    # 3) hostname
    for word, typ in (("iphone", "phone"), ("ipad", "phone"), ("android", "phone"), ("galaxy", "phone"), ("pixel", "phone"),
                      ("macbook", "computer"), ("desktop-", "computer"), ("laptop", "computer"), ("-pc", "computer"),
                      ("printer", "printer"), ("tv", "tv"), ("chromecast", "tv"), ("playstation", "gaming"), ("ps5", "gaming"),
                      ("xbox", "gaming"), ("nas", "nas"), ("cam", "camera"), ("esp", "iot"), ("shelly", "iot"), ("tasmota", "iot")):
        if word in host:
            return typ

    # 4) OS
    os_text = f"{os_guess or ''} {os_type or ''}".lower()
    if any(k in os_text for k in ("ios", "android", "phone")):
        return "phone"
    if "printer" in os_text:
        return "printer"
    if any(k in os_text for k in ("windows", "mac os", "macos")):
        return "computer"
    if "webcam" in os_text:
        return "camera"
    if "router" in os_text or "wap" in os_text or "switch" in os_text:
        return "router"

    if t:
        return t

    # 5) DHCP parmak izi (gizli MAC'li cihazlarda üretici bilgisi yoktur)
    if os_family == "android":
        return "phone"
    if os_family == "apple":
        # 62078 (iOS lockdownd) veya gizli MAC → büyük olasılıkla iPhone/iPad
        return "phone" if (62078 in ports or is_random_mac) else "computer"
    if os_family == "windows":
        return "computer"
    if os_family == "embedded":
        return "iot"
    if 62078 in ports:
        return "phone"

    # 6) üretici
    vt = _match(vendor or "", VENDOR_HINTS)
    if vt:
        return vt
    if 445 in ports or 3389 in ports:
        return "computer"
    if 22 in ports and "linux" in os_text:
        return "computer"
    return "unknown"


def label(device_type: str) -> str:
    from app.i18n import t

    return t(f"type.{device_type if device_type in TYPES else 'unknown'}")


def icon(device_type: str) -> str:
    return TYPES.get(device_type, TYPES["unknown"])
