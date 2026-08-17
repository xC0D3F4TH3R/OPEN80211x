"""
Reconnaissance module.

  * scan_networks  - discover all nearby APs (beacons/probe-responses)
  * scan_clients   - find client devices probing/associated
  * channel_hop    - sweep channels during a scan
  * full_recon     - combined guided recon workflow
"""
import threading
import time
from collections import defaultdict

from open80211.core import ui
from open80211.core.config import CONFIG, check_platform
from open80211.core import netutils as nu
from open80211.core.interfaces import set_channel
from open80211.core.targets import add_aps, add_clients, log_event

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Elt, RadioTap
except Exception:
    pass


def _channels_2ghz() -> list:
    return list(range(1, 14))


def _channels_5ghz() -> list:
    return [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124,
            128, 132, 136, 140, 149, 153, 157, 161, 165]


def scan_networks(iface: str, channels: list = None, dwell: float = 0.5,
                  duration: float = 12.0, include_5ghz: bool = False) -> list:
    """
    Passive scan for access points. Returns list of dicts:
      {bssid, ssid, channel, enc, signal, clients_detected, times_seen, pcap}
    """
    if not check_platform("linux"):
        return []
    band = "2.4+5GHz" if include_5ghz else "2.4GHz"
    ui.section("Scanning for Access Points", f"iface={iface} band={band} duration={int(duration)}s")
    channels = channels or (_channels_2ghz() + (_channels_5ghz() if include_5ghz else []))
    stop = threading.Event()
    aps = defaultdict(lambda: {"ssid": "", "channel": 0, "enc": "?",
                               "signal": -100, "clients": set(), "times": 0})

    def hopper():
        i = 0
        while not stop.is_set():
            ch = channels[i % len(channels)]
            set_channel(iface, ch)
            i += 1
            time.sleep(dwell)

    def handler(pkt):
        try:
            if pkt.haslayer(Dot11):
                d = pkt.getlayer(Dot11)
                if d.type != 0:
                    return
                bssid = nu.norm_mac(d.addr3 or d.addr2)
                if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                    return
                sig = -100
                rt = pkt.getlayer(RadioTap)
                if rt is not None and hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal:
                    sig = int(rt.dBm_AntSignal)
                ap = aps[bssid]
                ap["times"] += 1
                if d.subtype == 8 or d.subtype == 5:
                    if not ap["ssid"]:
                        ap["ssid"] = nu.ssid_of(pkt)
                    ap["enc"] = nu.encryption_info(pkt)
                    # extract channel from DS element
                    for elt in nu._elts(pkt):
                        if elt.ID == 3 and len(elt.info) == 1:
                            ap["channel"] = elt.info[0]
                            break
                    if sig > ap["signal"]:
                        ap["signal"] = sig
                elif d.subtype == 4:
                    target = nu.ssid_of(pkt)
                    for b, info in aps.items():
                        if target and (target == info["ssid"] or target == ""):
                            info["clients"].add(d.addr2)
                    if not target:
                        for b, info in aps.items():
                            info["clients"].add(d.addr2)
        except Exception:
            pass

    t_hop = threading.Thread(target=hopper, daemon=True)
    t_hop.start()
    ui.info("Hopping channels... (Ctrl+C to stop early)")
    try:
        sniff(iface=iface, prn=handler, store=False, timeout=duration)
    except Exception as e:
        ui.error(f"Capture failed: {e}")
        stop.set()
        return []
    stop.set()

    rows = []
    for bssid, a in aps.items():
        rows.append({
            "bssid": bssid, "ssid": a["ssid"] or "<hidden>",
            "channel": a["channel"], "enc": a["enc"], "signal": a["signal"],
            "clients_detected": list(a["clients"]), "times_seen": a["times"],
        })
    rows.sort(key=lambda r: -r["signal"])
    add_aps(rows)
    log_event("recon", f"AP scan: {len(rows)} networks")
    return rows


def show_networks(nets: list) -> int:
    """Render AP list, returns chosen index or -1."""
    if not nets:
        ui.warn("No access points found.")
        return -1
    table_rows = []
    for n in nets:
        table_rows.append([
            n["bssid"], n["ssid"], n["channel"], n["enc"], f"{n['signal']}dBm",
            len(n["clients_detected"]), n["times_seen"]
        ])
    ui.show_table("Discovered Access Points", ["BSSID", "SSID", "CH", "Encryption",
                                               "Signal", "#Clients", "Beacons"],
                  table_rows)
    return 0


def scan_clients(iface: str, bssid: str = "", channel: int = 0,
                 duration: float = 15.0) -> list:
    """Passive client discovery (probes + associated clients)."""
    if not check_platform("linux"):
        return []
    ui.section("Scanning for Clients", f"target BSSID={bssid or 'ALL'}")
    if channel:
        set_channel(iface, channel)
    bssid = nu.norm_mac(bssid) if bssid else ""
    clients = defaultdict(lambda: {"probes": [], "associated_to": None,
                                   "signal": -100, "last_seen": 0})

    def handler(pkt):
        try:
            if not pkt.haslayer(Dot11):
                return
            d = pkt.getlayer(Dot11)
            mac = nu.norm_mac(d.addr2)
            if not mac or mac == "ff:ff:ff:ff:ff:ff":
                return
            sig = -100
            rt = pkt.getlayer(RadioTap)
            if rt is not None and hasattr(rt, "dBm_AntSignal"):
                sig = int(rt.dBm_AntSignal or -100)
            c = clients[mac]
            c["last_seen"] = time.time()
            if sig > c["signal"]:
                c["signal"] = sig
            if d.type == 0 and d.subtype == 4:  # probe request
                probe = nu.ssid_of(pkt)
                if probe and probe not in c["probes"]:
                    c["probes"].append(probe)
            # associated when ToDS data to target bssid
            if bssid and d.type == 2:
                if nu.norm_mac(d.addr1) == bssid or nu.norm_mac(d.addr3) == bssid:
                    c["associated_to"] = bssid
        except Exception:
            pass

    ui.info(f"Listening for client traffic for {int(duration)}s...")
    try:
        sniff(iface=iface, prn=handler, store=False, timeout=duration)
    except Exception as e:
        ui.error(f"Capture failed: {e}")
        return []
    rows = []
    for mac, c in clients.items():
        rows.append({"mac": mac, "probes": c["probes"],
                     "associated_to": c["associated_to"], "signal": c["signal"],
                     "last_seen": c["last_seen"]})
    rows.sort(key=lambda r: -r["signal"])
    add_clients(rows)
    log_event("recon", f"client scan: {len(rows)} devices")
    return rows


def show_clients(clients: list) -> None:
    if not clients:
        ui.warn("No clients found.")
        return
    rows = [[c["mac"], ",".join(c["probes"]) or "-", c["associated_to"] or "-",
             f"{c['signal']}dBm"] for c in clients]
    ui.show_table("Discovered Clients", ["MAC", "Probed SSIDs", "Associated", "Signal"],
                  rows)


def wardrive(iface: str, duration: float = 120.0, include_5ghz: bool = False) -> str:
    """Continuous wardriving: hop channels, log every AP to CSV + JSON."""
    if not check_platform("linux"):
        return ""
    ui.section("Wardriving", f"duration={int(duration)}s 5GHz={include_5ghz}")
    nets = scan_networks(iface, duration=duration, include_5ghz=include_5ghz)
    csv_path = CONFIG.session_dir / "wardrive.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        import csv
        w = csv.writer(f)
        w.writerow(["bssid", "ssid", "channel", "enc", "signal", "clients", "beacons"])
        for n in sorted(nets, key=lambda r: r["signal"], reverse=True):
            w.writerow([n["bssid"], n["ssid"], n["channel"], n["enc"],
                        n["signal"], len(n["clients_detected"]), n["times_seen"]])
    ui.ok(f"Wardrive log -> {csv_path}")
    return str(csv_path)


def recon_menu(iface: str) -> None:
    """Standalone recon menu (reachable from main menu)."""
    while True:
        choice = ui.menu("Recon", [
            "Scan APs (2.4GHz)",
            "Scan APs (2.4 + 5GHz)",
            "Scan clients of a specific AP",
            "Wardrive (log everything)",
            "Guided full recon",
        ])
        if choice == 0:
            return
        if choice == 1:
            nets = scan_networks(iface)
            show_networks(nets)
        elif choice == 2:
            nets = scan_networks(iface, include_5ghz=True)
            show_networks(nets)
        elif choice == 3:
            bssid = ui.ask("AP BSSID")
            ch = ui.ask_int("Channel", default=6)
            cl = scan_clients(iface, bssid, ch)
            show_clients(cl)
        elif choice == 4:
            dur = ui.ask_int("Duration (s)", default=120)
            wardrive(iface, dur)
        elif choice == 5:
            full_recon(iface)


def full_recon(iface: str) -> dict:
    """Guided recon: scan networks, then optionally clients of a target."""
    nets = scan_networks(iface)
    show_networks(nets)
    chosen = 0
    if len(nets) > 1:
        pick = ui.ask_int("Select AP to inspect (0 = skip)", default=1)
        chosen = pick - 1 if 0 < pick <= len(nets) else -1
    report = {"networks": nets, "clients": []}
    if chosen >= 0 and nets:
        net = nets[chosen]
        ui.ok(f"Scanning clients of {net['ssid']} ({net['bssid']}) ch {net['channel']}")
        cl = scan_clients(iface, net["bssid"], net["channel"])
        show_clients(cl)
        report["clients"] = cl
        p = CONFIG.save("recon_report", report)
        ui.ok(f"Report saved: {p}")
    return report