"""
Wireless / network interface management.

Discovers interfaces, detects Wi-Fi adapters, enables monitor mode,
hops channels, and reports link state. Uses `psutil` + `netifaces` for
discovery and `iw`/`ip` (Linux) for wireless control.
"""
import random
import re
import subprocess
import socket

from open80211.core import ui
from open80211.core.config import is_linux, is_windows


def _run(cmd: list, timeout: int = 8) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""


def list_interfaces() -> list:
    """
    Return a list of interface dicts:
      {name, mac, ips[], flags, type ('wireless'|'wired'|'loopback'), chipset}
    """
    ifaces = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, st in stats.items():
            mac = ""
            ips = []
            for a in addrs.get(name, []):
                if a.family == socket.AF_LINK or a.family == -1:
                    mac = a.address
                elif a.family == socket.AF_INET:
                    ips.append(a.address)
            kind = "loopback" if st.isup and mac == "" and name == "lo" else "wired"
            ifaces.append({
                "name": name, "mac": mac, "ips": ips,
                "flags": f"{'UP' if st.isup else 'DOWN'},{st.speed}Mbps",
                "type": kind,
            })
    except Exception:
        ifaces = _psutil_fallback()
    # Mark wireless ones
    for i in ifaces:
        i["type"] = "wireless" if is_wireless(i["name"]) else i["type"]
    return ifaces


def _psutil_fallback() -> list:
    """Use `ip` output on Linux if psutil is unavailable."""
    out = _run(["ip", "-o", "link", "show"])
    res = []
    for line in out.splitlines():
        m = re.search(r"\d+:\s+(\S+?)[:@].*link/\S+\s+([0-9a-f:]{17})", line)
        if m:
            res.append({"name": m.group(1), "mac": m.group(2), "ips": [],
                        "flags": "?", "type": "wired"})
    return res


def is_wireless(name: str) -> bool:
    if not is_linux():
        return False
    if os_wireless_path(name) or _run(["iw", "dev", name, "info"]):
        return True
    return False


def os_wireless_path(name: str) -> bool:
    from pathlib import Path
    return (Path("/sys/class/net") / name / "wireless").exists()


def get_mac(name: str) -> str:
    for i in list_interfaces():
        if i["name"] == name:
            return i["mac"]
    return ""


def get_ip(name: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        for i in list_interfaces():
            if i["name"] == name and i["ips"]:
                return i["ips"][0]
    return ""


def pick_interface(prompt: str = "Select an interface") -> str:
    """Interactive interface picker."""
    ifaces = list_interfaces()
    if not ifaces:
        ui.error("No network interfaces found.")
        return ""
    wireless = [i["name"] for i in ifaces if i["type"] == "wireless"]
    wired = [i["name"] for i in ifaces if i["type"] != "wireless"]
    options = []
    for n in wireless:
        options.append(f"{n}  [dim](wireless)[/dim]")
    for n in wired:
        options.append(f"{n}  [dim](wired)[/dim]")
    pick = ui.menu(prompt, options)
    if not pick:
        return ""
    target = wireless + wired
    return target[pick - 1]


def set_monitor_mode(iface: str, on: bool) -> bool:
    """Enable (on=True) or disable monitor mode on a wireless interface (Linux)."""
    if not is_linux():
        ui.warn("Monitor mode is only available on Linux.")
        return False
    mode = "monitor" if on else "managed"
    ui.info(f"Setting {iface} to {mode} mode...")
    if on:
        # iw phy info can be slow; do the common steps
        for cmd in (
            ["ip", "link", "set", iface, "down"],
            ["iw", iface, "set", "type", mode],
            ["ip", "link", "set", iface, "up"],
        ):
            _run(cmd)
        ok = "monitor" in _run(["iw", iface, "info"])
        if ok:
            ui.ok(f"{iface} is now in monitor mode.")
        else:
            ui.error("Monitor mode could not be verified. Try: airmon-ng start wlan0")
        return ok
    for cmd in (
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", "managed"],
        ["ip", "link", "set", iface, "up"],
    ):
        _run(cmd)
    return True


def set_channel(iface: str, channel: int) -> bool:
    if not is_linux():
        return False
    if _run(["iw", iface, "set", "channel", str(channel)]):
        return True
    return "monitor" in _run(["iw", iface, "info"])


def hop_channels(iface: str, channels: list, hold: float = 0.4, stop=None):
    """Channel-hopping loop; yields current channel. Stop via threading.Event."""
    if not channels:
        channels = list(range(1, 14))
    i = 0
    while not stop or not stop.is_set():
        ch = channels[i % len(channels)]
        set_channel(iface, ch)
        i += 1
        import time
        time.sleep(hold)


def random_mac() -> str:
    """Generate a random locally-administered unicast MAC."""
    oui = random.randint(0x00, 0xFF)
    return f"{oui:02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}" \
           f":{random.randint(0,255):02x}:{random.randint(0,255):02x}:" \
           f"{random.randint(0,255):02x}"


def spoof_mac(iface: str, mac: str) -> bool:
    if not is_linux():
        return False
    _run(["ip", "link", "set", iface, "down"])
    _run(["ip", "link", "set", iface, "address", mac])
    _run(["ip", "link", "set", iface, "up"])
    return get_mac(iface).lower() == mac.lower()


def get_gateway(iface: str = "") -> str:
    """Best-effort default gateway via routing table."""
    if is_linux():
        out = _run(["ip", "route"])
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    try:
        import psutil
        net = psutil.net_connections(kind="inet")
        # fallback: parse /proc/net/route
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000":
                gw = f[2]
                return socket.inet_ntoa(bytes.fromhex(gw)[::-1])
    except Exception:
        pass
    return ""


def system_command(cmd: str, timeout: int = 60) -> tuple:
    """Run an external tool and return (rc, stdout)."""
    try:
        p = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except FileNotFoundError:
        return 1, "tool not found"
    except Exception as e:
        return 1, str(e)


def which(tool: str) -> bool:
    """Check an external tool exists in PATH."""
    from shutil import which as sh_which
    return sh_which(tool) is not None