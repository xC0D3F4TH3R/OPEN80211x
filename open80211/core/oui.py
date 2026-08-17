"""
MAC OUI vendor database used for realistic MAC spoofing.

A compact mapping of the most common 24-bit IEEE OUIs to vendor names,
plus helpers to generate believable random MACs that impersonate a
chosen (or random) hardware vendor. Parsing `oui.txt` from
https://standards-oui.ieee.org/oui/oui.txt is also supported when
present on disk.
"""
import random
import re
from pathlib import Path

from open80211.core.config import SUITE_ROOT

# (oui_hex_no_colons, vendor) - top ~120 vendors by deployed devices.
_OUI_TABLE = [
    ("00:1A:11", "Intel"),
    ("00:1F:29", "Intel"),
    ("00:1C:BF", "Intel"),
    ("00:13:E8", "Intel"),
    ("00:1E:67", "Intel"),
    ("00:1B:21", "Intel"),
    ("00:23:24", "Intel"),
    ("00:15:00", "Intel"),
    ("00:22:41", "Samsung"),
    ("00:23:D4", "Samsung"),
    ("00:1E:68", "Samsung"),
    ("00:23:32", "Samsung"),
    ("00:12:FB", "Samsung"),
    ("00:11:22", "Samsung"),
    ("00:24:54", "Samsung"),
    ("A4:77:33", "Samsung"),
    ("E4:93:AB", "Samsung"),
    ("BC:85:56", "Samsung"),
    ("00:23:DF", "Apple"),
    ("00:25:00", "Apple"),
    ("00:26:BB", "Apple"),
    ("00:26:08", "Apple"),
    ("F0:18:98", "Apple"),
    ("3C:07:54", "Apple"),
    ("AC:BC:32", "Apple"),
    ("00:1A:B9", "Apple"),
    ("78:27:0B", "Samsung"),
    ("00:23:5A", "HTC"),
    ("00:21:39", "HTC"),
    ("00:18:1A", "HTC"),
    ("00:0F:88", "HTC"),
    ("00:1E:8B", "AsusTek"),
    ("00:24:8C", "AsusTek"),
    ("00:1B:FC", "AsusTek"),
    ("00:25:53", "AsusTek"),
    ("00:1C:B3", "AsusTek"),
    ("00:24:42", "Motorola"),
    ("00:1A:7D", "Motorola"),
    ("00:16:1E", "Motorola"),
    ("00:1B:67", "Motorola"),
    ("00:0A:28", "Motorola"),
    ("00:1E:B5", "Motorola"),
    ("00:18:DE", "LGE"),
    ("00:1A:88", "LGE"),
    ("00:1B:B6", "LGE"),
    ("00:23:F0", "LGE"),
    ("00:21:5C", "SonyEricsson"),
    ("00:26:36", "SonyMobile"),
    ("00:24:DA", "Sony"),
    ("00:0B:FD", "Sony"),
    ("00:25:04", "Sony"),
    ("00:1F:3B", "Sony"),
    ("00:22:7E", "Sony"),
    ("00:21:3B", "Nokia"),
    ("00:02:77", "Nokia"),
    ("00:1C:8A", "Nokia"),
    ("00:1E:3F", "Nokia"),
    ("00:23:36", "Nokia"),
    ("00:1B:4F", "Nokia"),
    ("00:1C:7B", "Huawei"),
    ("00:25:9E", "Huawei"),
    ("78:2B:CB", "Huawei"),
    ("E4:9A:79", "Huawei"),
    ("00:1A:2B", "Huawei"),
    ("00:23:5F", "Xiaomi"),
    ("28:6C:07", "Xiaomi"),
    ("BC:02:6F", "Xiaomi"),
    ("00:1B:11", "Dell"),
    ("00:21:9B", "Dell"),
    ("00:26:B9", "Dell"),
    ("00:14:22", "Dell"),
    ("00:19:B9", "Dell"),
    ("F8:BC:12", "Dell"),
    ("00:17:66", "HP"),
    ("00:1D:7D", "HP"),
    ("00:25:B3", "HP"),
    ("00:21:5A", "HP"),
    ("3C:D9:2B", "HP"),
    ("00:1A:6B", "Lenovo"),
    ("00:26:2D", "Lenovo"),
    ("54:EE:75", "Lenovo"),
    ("00:14:85", "D-Link"),
    ("00:1B:11", "Dell"),
    ("00:1C:F0", "D-Link"),
    ("00:1E:58", "D-Link"),
    ("00:24:01", "D-Link"),
    ("00:26:5A", "D-Link"),
    ("00:1B:2F", "Netgear"),
    ("00:22:3F", "Netgear"),
    ("00:24:B2", "Netgear"),
    ("00:26:86", "Netgear"),
    ("00:0F:B5", "Netgear"),
    ("20:4E:7F", "Netgear"),
    ("00:16:CB", "Cisco"),
    ("00:18:39", "Cisco"),
    ("00:1A:A1", "Cisco"),
    ("00:1B:0C", "Cisco"),
    ("00:1F:CA", "Cisco"),
    ("00:24:C4", "Cisco"),
    ("00:26:98", "Cisco"),
    ("00:26:CB", "Cisco"),
    ("00:50:56", "VMware"),
    ("00:0C:29", "VMware"),
    ("00:05:69", "VMware"),
    ("00:1C:42", "Parallels"),
    ("00:25:5D", "Microsoft"),
    ("00:03:FF", "Microsoft"),
    ("48:3F:DA", "Microsoft"),
    ("00:15:5D", "Hyper-V"),
    ("00:16:3E", "Xen"),
    ("00:1B:8B", "RaspberryPi"),
    ("B8:27:EB", "RaspberryPi"),
    ("DC:A6:32", "RaspberryPi"),
    ("E4:5F:01", "RaspberryPi"),
    ("00:0C:83", "Espressif"),
    ("18:FE:34", "Espressif"),
    ("24:0A:C4", "Espressif"),
    ("00:13:CE", "Broadcom"),
    ("00:22:15", "Broadcom"),
    ("00:1F:33", "Broadcom"),
    ("00:23:68", "Broadcom"),
    ("00:0E:6D", "Qualcomm"),
    ("00:1A:45", "Qualcomm"),
    ("00:21:6A", "Qualcomm"),
    ("00:1B:AF", "Qualcomm"),
    ("00:24:11", "Qualcomm"),
    ("00:1E:87", "Realtek"),
    ("00:19:2D", "Realtek"),
    ("00:21:9F", "Realtek"),
    ("00:25:86", "Realtek"),
    ("00:0E:6A", "Realtek"),
    ("00:22:16", "Atheros"),
    ("00:03:7F", "Atheros"),
    ("00:23:14", "Atheros"),
    ("00:1E:4C", "Atheros"),
    ("00:1F:3B", "MediaTek"),
    ("00:23:EE", "MediaTek"),
    ("00:0C:42", "MediaTek"),
    ("00:0C:E7", "MediaTek"),
    ("00:0A:F2", "Zyxel"),
    ("00:1A:2F", "Zyxel"),
    ("00:1C:DF", "Zyxel"),
    ("00:18:0F", "Xerox"),
    ("00:1F:3C", "TomTom"),
    ("00:22:2F", "Furukawa"),
    ("00:17:C8", "Kyocera"),
    ("00:20:A6", "Brother"),
    ("00:26:73", "Brother"),
    ("00:1B:81", "EPSON"),
    ("00:00:2E", "EPSON"),
    ("00:1C:5E", "GoPro"),
    ("00:13:47", "Garmin"),
    ("00:0B:4F", "Garmin"),
    ("00:22:58", "Garmin"),
    ("00:18:18", "Panasonic"),
    ("00:21:86", "Panasonic"),
    ("00:14:C2", "ZTE"),
    ("00:22:3B", "ZTE"),
    ("00:1D:D1", "ZTE"),
    ("00:1B:0C", "Mikrotik"),
    ("00:23:2E", "Mikrotik"),
    ("00:1C:0E", "TP-Link"),
    ("00:26:19", "TP-Link"),
    ("50:C7:BF", "TP-Link"),
    ("30:1B:BA", "TP-Link"),
    ("00:1D:0F", "TP-Link"),
    ("00:25:9C", "TP-Link"),
    ("00:1A:E9", "Linksys"),
    ("00:1B:57", "Linksys"),
    ("00:1F:6C", "Linksys"),
    ("00:23:69", "Linksys"),
    ("00:24:3B", "Linksys"),
    ("C0:56:27", "Linksys"),
    ("00:0B:86", "Acer"),
    ("00:1D:72", "Acer"),
    ("00:23:8E", "Acer"),
    ("00:26:2C", "Acer"),
    ("00:1F:16", "Acer"),
    ("00:25:64", "Acer"),
]

# normalize: strip colons, lowercase -> vendor
_OUI_LOOKUP = {oui.replace(":", "").lower(): vendor for oui, vendor in _OUI_TABLE}


def lookup_vendor(mac: str) -> str:
    """Return the vendor name for a MAC, or '' if unknown."""
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hexs) < 6:
        return ""
    return _OUI_LOOKUP.get(hexs[:6], "")


def list_vendors() -> list:
    """All known (oui, vendor) pairs, sorted."""
    return sorted((oui, vendor) for oui, vendor in _OUI_TABLE)


def vendor_ouis(vendor_substr: str) -> list:
    """Return OUIs whose vendor name contains substring (case-insensitive)."""
    s = vendor_substr.lower()
    return [oui for oui, v in _OUI_TABLE if s in v.lower()]


def random_mac_with_vendor(vendor_substr: str = "") -> str:
    """Random MAC. If vendor_substr given, use a matching OUI prefix."""
    if vendor_substr:
        ouis = vendor_ouis(vendor_substr)
        if ouis:
            oui = random.choice(ouis).replace(":", "")
        else:
            oui = f"{random.randint(0, 0xFF):02x}{random.randint(0, 0xFF):02x}" \
                  f"{random.randint(0, 0xFF):02x}"
    else:
        oui = random.choice(list(_OUI_LOOKUP.keys()))[:6]
    rest = "".join(f"{random.randint(0, 0xFF):02x}" for _ in range(3))
    mac = oui + rest
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def load_ieee_oui_file(path: str | Path = "") -> int:
    """
    Optionally enrich the table from a full IEEE oui.txt file.
    Returns number of entries loaded. Runs on the first call only when
    a file is explicitly supplied or found in the repo.
    """
    global _OUI_LOOKUP
    path = Path(path) if path else SUITE_ROOT / "oui.txt"
    if not path.exists():
        return 0
    count = 0
    pat = re.compile(r"^\s*([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(base 16\)\s+(.+)$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pat.match(line)
        if m:
            oui = f"{m.group(1)}{m.group(2)}{m.group(3)}".lower()
            _OUI_LOOKUP[oui] = m.group(4).strip()
            count += 1
    return count
