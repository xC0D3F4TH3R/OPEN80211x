"""
Interactive main menu - the face of the suite.

Professional workflow, not a menu zoo. The Engagement Console is the
cockpit: it chains the killchains (scan -> attack -> crack -> report)
and keeps one shared target registry. The two attack modes remain
one keypress away.

  01  Engagement Console   - killchain wizards, target registry, timeline
  02  ATTACK WITHOUT MONITOR MODE
  03  ATTACK WITH MONITOR MODE
  04  Workspaces           - create/resume named engagements
  05  Report / Results
  06  Setup & Interface
  07  Help
"""
from open80211.core import ui
from open80211.core.config import CONFIG, is_linux, require_privileges
from open80211.core.interfaces import (pick_interface, set_monitor_mode,
                                       set_channel, spoof_mac, random_mac,
                                       list_interfaces, get_mac, get_ip)


def choose_interface() -> bool:
    """Interactive interface selection; returns True if a usable iface chosen."""
    name = pick_interface()
    if not name:
        ui.warn("No interface selected.")
        return False
    CONFIG.interface = name
    ui.ok(f"Using interface: {name}  MAC={get_mac(name)}  IP={get_ip(name)}")
    return True


def ensure_interface() -> bool:
    if CONFIG.interface or choose_interface():
        return True
    return False


def setup_menu() -> None:
    while True:
        choice = ui.menu("Setup & Interface", [
            "Select wireless interface",
            "Enable monitor mode",
            "Set channel",
            "Spoof MAC address",
            "Show current status",
            "Check dependencies",
        ])
        if choice == 0:
            return
        if choice == 1:
            choose_interface()
        elif choice == 2:
            if not is_linux():
                ui.warn("Monitor mode requires Linux.")
                continue
            if not ensure_interface():
                continue
            set_monitor_mode(CONFIG.interface, True)
        elif choice == 3:
            if not ensure_interface():
                continue
            ch = ui.ask_int("Channel (1-13)", default=6)
            if set_channel(CONFIG.interface, ch):
                CONFIG.channel = ch
                ui.ok(f"Channel set to {ch}")
            else:
                ui.error("Could not set channel. Is the interface in monitor mode?")
        elif choice == 4:
            if not ensure_interface():
                continue
            new = ui.ask("New MAC (blank = random)", default="")
            mac = new or random_mac()
            if spoof_mac(CONFIG.interface, mac):
                ui.ok(f"MAC spoofed to {mac}")
            else:
                ui.warn("MAC spoofing failed (may need Linux/root).")
        elif choice == 5:
            ui.show_table("Status", ["Item", "Value"], [
                ["Interface", CONFIG.interface or "(none)"],
                ["MAC", get_mac(CONFIG.interface) or "-"],
                ["IP", get_ip(CONFIG.interface) or "-"],
                ["Channel", CONFIG.channel],
                ["Results dir", str(CONFIG.session_dir)],
                ["Platform", __import__("platform").platform()],
            ])
        elif choice == 6:
            from open80211.core.interfaces import which
            from open80211.core.integrations import detect_tools
            rows = []
            for name, required in [("scapy", True), ("rich", True),
                                   ("pycryptodome", True), ("cryptography", True)]:
                ok = False
                try:
                    mod = {"scapy": "scapy", "rich": "rich",
                           "pycryptodome": "Crypto", "cryptography": "cryptography"}[name]
                    __import__(mod)
                    ok = True
                except ImportError:
                    ok = False
                rows.append([name, "[green]OK[/green]" if ok else "[red]missing[/red]", "core"])
            for name, ok in detect_tools().items():
                rows.append([name, "[green]OK[/green]" if ok else "[dim]not found[/dim]",
                             "optional"])
            ui.show_table("Dependencies", ["Tool", "Status", "Type"], rows)
            ui.info("Install core deps: pip install -r requirements.txt")
            ui.info("External: apt install hostapd hostapd-mana dnsmasq aircrack-ng "
                    "reaver tcpdump iw")


# --------------------------------------------------------------------------
# ATTACK MODE 1 : WITHOUT monitor mode
# --------------------------------------------------------------------------

def attack_without_monitor(iface: str) -> None:
    """Everything that runs on a managed/connected interface (or no card)."""
    while True:
        choice = ui.menu("Attack WITHOUT Monitor Mode", [
            "Spoofing / Identity (MAC, IP, ARP, 802.11 MAC)",
            "MITM suite (ARP/DNS/SSL-strip/HTTPS decrypt)",
            "LAN / Network attacks",
            "Brute force (SSH/FTP/HTTP/Telnet/SMB)",
            "Bluetooth attack suite (classic + BLE)",
            "Cellular / SIM / cell-tower suite",
            "IoT pentest suite (MQTT/UPnP/RTSP/CoAP)",
            "Packet sniffing (managed mode)",
        ])
        if choice == 0:
            return
        if choice == 1:
            from open80211.modules.spoof import spoof_menu
            spoof_menu(iface)
        elif choice == 2:
            from open80211.modules.mitm import mitm_menu
            mitm_menu(iface)
        elif choice == 3:
            from open80211.modules.lan import lan_menu
            lan_menu(iface)
        elif choice == 4:
            from open80211.modules.bruteforce import brute_menu
            brute_menu(iface)
        elif choice == 5:
            from open80211.modules.bluetooth import bt_menu
            bt_menu(iface)
        elif choice == 6:
            from open80211.modules.cellular import cell_menu
            cell_menu(iface)
        elif choice == 7:
            from open80211.modules.iot import iot_menu
            iot_menu(iface)
        elif choice == 8:
            from open80211.modules.capture import interactive_capture
            interactive_capture(iface)


# --------------------------------------------------------------------------
# ATTACK MODE 2 : WITH monitor mode
# --------------------------------------------------------------------------

def attack_with_monitor(iface: str) -> None:
    """Raw 802.11 air attacks - requires monitor mode + injection adapter."""
    if not is_linux():
        ui.warn("Monitor-mode attacks require Linux + a monitor-capable "
                "Wi-Fi adapter (e.g. Kali + ALFA).")
        ui.info("On other platforms use 'Attack WITHOUT monitor mode' "
                "for LAN/MITM/Bluetooth/cellular/IoT.")
        return
    ui.info("Enable monitor mode in Setup if not already active.")
    while True:
        choice = ui.menu("Attack WITH Monitor Mode", [
            "Recon (scan APs & clients, wardrive)",
            "Attack suite (deauth/floods/WPS/injection)",
            "Evil AP / Evil twin suite",
            "WEP suite (legacy)",
            "Analysis (handshake/PMKID/crack/decrypt)",
            "Capture raw 802.11 (monitor)",
        ])
        if choice == 0:
            return
        if choice == 1:
            from open80211.modules.recon import recon_menu
            recon_menu(iface)
        elif choice == 2:
            from open80211.modules.attacks import attack_menu
            attack_menu(iface)
        elif choice == 3:
            from open80211.modules.evilap import evil_ap_menu
            evil_ap_menu(iface)
        elif choice == 4:
            from open80211.modules.wep import wep_menu
            wep_menu(iface)
        elif choice == 5:
            from open80211.modules.analysis import analysis_menu
            analysis_menu(iface)
        elif choice == 6:
            from open80211.modules.capture import interactive_capture
            interactive_capture(iface)


# --------------------------------------------------------------------------
# Help / docs
# --------------------------------------------------------------------------

def help_menu() -> None:
    ui.section("Help / Documentation", "How the suite is organized")
    ui.info("""
[bold cyan]ENGAGEMENT CONSOLE (recommended start)[/bold cyan]
  One cockpit, one shared target registry, guided killchains:
    1. Open Engagement Console -> Quick actions
    2. Pick a killchain (WPA2 / LAN / IoT / Bluetooth)
    3. It chains: recon -> attack -> crack -> report automatically
  Every module also writes its findings into the shared registry, so the
  report at the end covers the whole engagement.

[bold cyan]TWO OPERATION MODES[/bold cyan]
  ATTACK WITHOUT MONITOR MODE - works on any connected interface (or none):
    Spoofing (MAC/IP/ARP), MITM (ARP/DNS/SSL-strip/HTTPS decrypt),
    LAN attacks, brute force, Bluetooth, Cellular/SIM, IoT, packet sniffing.
  ATTACK WITH MONITOR MODE   - needs Linux + monitor-mode adapter:
    Recon, deauth/floods, WPS, evil AP / evil twin, WEP, handshake/PMKID
    capture, cracking and WPA2 traffic decryption.

[bold cyan]WORKSPACES[/bold cyan]
  Keep each client engagement separate: create a workspace, switch/resume
  anytime, everything (targets, captures, notes) is stored per workspace.

[bold cyan]KEY TERMS[/bold cyan]
  BSSID     - AP MAC address          SSID - network name
  Monitor mode  - capture raw 802.11 frames
  Injection     - send custom frames (deauth/floods)
  Handshake     - 4-way WPA key exchange needed for cracking
  PMKID         - hash sent by AP during handshake (no client needed)
  PMF / 802.11w - management frame protection (blocks deauth)
  LLMNR/NBT-NS  - legacy name resolution that leaks NTLM hashes
  Karma/MANA    - answering every probe with a matching fake AP
  Evil twin     - clone of a real SSID to harvest handshakes/creds

[bold cyan]CRACKING VIA INDUSTRY TOOLS[/bold cyan]
  hashcat -m 22000 crack-<ssid>.hc22000 wordlist.txt
  aircrack-ng -b BSSID -w wordlist capture.pcap
  hashcat -m 5600 hashes-ntlmv2.txt wordlist.txt

[bold cyan]LEGAL[/bold cyan]
  Use ONLY on networks you own or have written authorization to test.
""")


# --------------------------------------------------------------------------
# Results / status
# --------------------------------------------------------------------------

def results_menu() -> None:
    ui.section("Session Results", str(CONFIG.session_dir))
    files = sorted(CONFIG.session_dir.glob("*"))
    if not files:
        ui.info("No results in this session yet.")
        return
    ui.show_table("Files", ["Name", "Size"], [
        [f.name, f"{f.stat().st_size} bytes"] for f in files
    ])
    p = ui.ask("File to view (name or blank)", default="")
    if p:
        target = CONFIG.session_dir / p
        if target.exists() and target.is_file():
            print(target.read_text(encoding="utf-8", errors="replace")[:4000])


# --------------------------------------------------------------------------
# Main menu
# --------------------------------------------------------------------------

def main_menu() -> None:
    ui.banner()
    ui.disclaimer()
    if not ui.confirm("Do you have authorization to test this network?", default=False):
        ui.error("Exiting. Ethical use only.")
        return
    require_privileges("many features (monitor mode, injection)")
    from open80211.core.config import bind_engagement
    bind_engagement()
    while True:
        label = f"Main Menu  [dim](iface: {CONFIG.interface or 'none'} · ws: {CONFIG.run_id})[/dim]"
        choice = ui.menu(label, [
            "Engagement Console (killchains + registry)",
            "Attack WITHOUT monitor mode",
            "Attack WITH monitor mode",
            "Workspaces",
            "Report / Session results",
            "Setup & Interface",
            "Help",
        ])
        if choice == 0:
            ui.ok("Goodbye. Stay legal.")
            return
        if choice == 1:
            from open80211.modules.engage import engage_menu
            engage_menu(CONFIG.interface or _auto_pick())
        elif choice == 2:
            attack_without_monitor(CONFIG.interface or _auto_pick())
        elif choice == 3:
            attack_with_monitor(CONFIG.interface or _auto_pick())
        elif choice == 4:
            from open80211.core.workspace import workspace_menu
            workspace_menu()
        elif choice == 5:
            from open80211.modules.report import report_menu
            report_menu()
        elif choice == 6:
            setup_menu()
        elif choice == 7:
            help_menu()


def _auto_pick() -> str:
    """Best-effort default interface for modules that need one."""
    try:
        ifaces = list_interfaces()
        for i in ifaces:
            if i.get("type") == "wireless":
                CONFIG.interface = i["name"]
                return i["name"]
        for i in ifaces:
            if i.get("name") != "lo":
                CONFIG.interface = i["name"]
                return i["name"]
    except Exception:
        pass
    return ""