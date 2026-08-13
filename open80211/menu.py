"""
Interactive main menu - the face of the suite.
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
            if not CONFIG.interface:
                choose_interface()
            set_monitor_mode(CONFIG.interface, True)
        elif choice == 3:
            if not CONFIG.interface:
                choose_interface()
            ch = ui.ask_int("Channel (1-13)", default=6)
            if set_channel(CONFIG.interface, ch):
                CONFIG.channel = ch
                ui.ok(f"Channel set to {ch}")
            else:
                ui.error("Could not set channel. Is the interface in monitor mode?")
        elif choice == 4:
            if not CONFIG.interface:
                choose_interface()
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


def help_menu() -> None:
    ui.section("Help / Documentation", "How the suite is organized")
    ui.info("""
[bold cyan]OPEN80211 WORKFLOW[/bold cyan]
  1. Setup   -> select interface, enable monitor mode
  2. Recon   -> discover APs + clients (2.4/5GHz, WPA3 detection), wardrive
  3. Capture -> sniff everything (tcpdump-style), save pcaps
  4. Attacks -> deauth, beacon/assoc/probe floods, WPS, injection test
  5. MITM    -> ARP/DNS spoof, SSL strip, HTTPS interception, credential harvesting
  6. Evil AP -> rogue AP (open/WPA2/WPA-EAP), captive portal, Karma/MANA
  7. LAN     -> host discovery, port scan, DHCP attacks, LLMNR/NBT-NS/mDNS
                poisoning + NTLMv2 capture (Responder-style)
  8. WEP     -> fake auth, ARP replay, PRGA, RC4 decrypt (legacy)
  9. Analysis-> handshake/PMKID capture, cracking, traffic decryption,
                hash exports (hashcat 22000 / hccapx / cowpatty)
 10. Report  -> HTML assessment report with findings + mitigations

[bold cyan]KEY TERMS[/bold cyan]
  BSSID     - AP MAC address          SSID - network name
  Monitor mode  - capture raw 802.11 frames
  Injection     - send custom frames (deauth/floods)
  Handshake     - 4-way WPA key exchange needed for cracking
  PMKID         - hash sent by AP during handshake (no client needed)
  PMF / 802.11w - management frame protection (blocks deauth)
  LLMNR/NBT-NS  - legacy name resolution that leaks NTLM hashes
  Karma/MANA    - answering every probe with a matching fake AP

[bold cyan]CRACKING VIA INDUSTRY TOOLS[/bold cyan]
  hashcat -m 22000 crack-<ssid>.hc22000 wordlist.txt
  aircrack-ng -b BSSID -w wordlist capture.pcap
  hashcat -m 5600 hashes-ntlmv2.txt wordlist.txt

[bold cyan]LEGAL[/bold cyan]
  Use ONLY on networks you own or have written authorization to test.
""")


def results_menu() -> None:
    import os
    from pathlib import Path
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


def main_menu() -> None:
    ui.banner()
    ui.disclaimer()
    if not ui.confirm("Do you have authorization to test this network?", default=False):
        ui.error("Exiting. Ethical use only.")
        return
    require_privileges("many features (monitor mode, injection)")
    while True:
        label = f"Main Menu  [dim](iface: {CONFIG.interface or 'none'})[/dim]"
        choice = ui.menu(label, [
            "Setup & Interface",
            "Recon (scan APs & clients)",
            "Capture / Tcpdump",
            "Attack Suite",
            "MITM Suite",
            "Evil AP Suite",
            "LAN / Network Suite",
            "WEP Suite (legacy)",
            "Analysis (crack / decrypt)",
            "Session Results",
            "Report Generator",
            "Help",
        ])
        if choice == 0:
            ui.ok("Goodbye. Stay legal.")
            return
        if choice == 1:
            setup_menu()
        elif choice == 2:
            from open80211.modules.recon import recon_menu
            if CONFIG.interface or choose_interface():
                recon_menu(CONFIG.interface)
        elif choice == 3:
            from open80211.modules.capture import interactive_capture
            if CONFIG.interface or choose_interface():
                interactive_capture(CONFIG.interface)
        elif choice == 4:
            from open80211.modules.attacks import attack_menu
            if CONFIG.interface or choose_interface():
                attack_menu(CONFIG.interface)
        elif choice == 5:
            from open80211.modules.mitm import mitm_menu
            if CONFIG.interface or choose_interface():
                mitm_menu(CONFIG.interface)
        elif choice == 6:
            from open80211.modules.evilap import evil_ap_menu
            if CONFIG.interface or choose_interface():
                evil_ap_menu(CONFIG.interface)
        elif choice == 7:
            from open80211.modules.lan import lan_menu
            if CONFIG.interface or choose_interface():
                lan_menu(CONFIG.interface)
        elif choice == 8:
            from open80211.modules.wep import wep_menu
            if CONFIG.interface or choose_interface():
                wep_menu(CONFIG.interface)
        elif choice == 9:
            from open80211.modules.analysis import analysis_menu
            if CONFIG.interface or choose_interface():
                analysis_menu(CONFIG.interface)
        elif choice == 10:
            results_menu()
        elif choice == 11:
            from open80211.modules.report import report_menu
            report_menu()
        elif choice == 12:
            help_menu()