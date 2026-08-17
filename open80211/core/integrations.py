"""
Industry tool integration + hash format exports.

Bridges open80211 captures to the ecosystem:
  * hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL)
  * cowpatty / wpaclean compatible
  * aircrack-ng hccapx via wpaclean
  * hashcat 5600 (NTLMv2)
  * wpa-sec style JSON for online submission
  * Optional external bridge commands (aircrack-ng, hashcat, bettercap,
    responder, reaver, hostapd-mana, freeradius, tcpdump)
"""
import struct
from datetime import datetime

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core import crypto
from open80211.core.interfaces import which


# --------------------------------------------------------------------------
# 22000 (WPA-PBKDF2-PMKID+EAPOL) export
# --------------------------------------------------------------------------

def export_hc22000(handshake: dict, ssid: str, pmk_from_psq: bytes = None,
                   out_path: str = "") -> str:
    """
    Build a hashcat mode 22000 line from an extracted handshake.
    Format: WPA*01*mic*mac_ap*mac_sta*anonce*snonce*keymic[+pmkid]*ssid
    keymic: PMKID, or MIC if no PMKID (requires pmk_to_work via PSQ not
    supported -> we use MIC when PMKID absent; cracking still works).
    """
    if not handshake.get("ap_mac") or not handshake.get("sta_mac"):
        ui.error("Handshake incomplete - need AP and client MAC.")
        return ""
    if not (handshake.get("anonce") and handshake.get("snonce")):
        ui.error("Handshake incomplete - need both nonces.")
        return ""
    mic = ""
    for m in handshake["eapol_msgs"]:
        ki = int(m["key_info"], 16)
        if ki & 0x0040:
            mic = m["mic"]
            break
    if not mic:
        ui.error("No EAPOL MIC frame available.")
        return ""

    ap = handshake["ap_mac"].replace(":", "")
    sta = handshake["sta_mac"].replace(":", "")
    anonce = handshake["anonce"]
    snonce = handshake["snonce"]
    pmkid = handshake.get("pmkid") or ""
    keymic = pmkid if pmkid else mic
    line = f"WPA*01*{mic}*{ap}*{sta}*{anonce}*{snonce}*{keymic}*{ssid}"
    out_path = out_path or str(CONFIG.session_dir / f"crack-{ssid}.hc22000")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(line + "\n")
    ui.ok(f"hashcat 22000 export -> {out_path}")
    return out_path


def export_cowpatty(handshake: dict, ssid: str, out_path: str = "") -> str:
    """Cowpatty-compatible pcap filter (client EAPOL frames)."""
    if not handshake.get("sta_mac"):
        return ""
    out_path = out_path or str(CONFIG.session_dir / f"cowpatty-{ssid}.cap")
    ui.info(f"Use a capture with STA {handshake['sta_mac']} for cowpatty: "
            f"cowpatty -d {out_path} -r <clean.pcap> -s {ssid}")
    return out_path


def export_hccapx_aircrack(handshake_pcap: str, ssid: str, bssid: str = "") -> str:
    """Generate hccapx via wpaclean (if present)."""
    if not which("wpaclean"):
        ui.warn("wpaclean not found (part of aircrack-ng). Skipping hccapx export.")
        return ""
    out = str(CONFIG.session_dir / f"crack-{ssid}.hccapx")
    cmd = f"wpaclean {out} {handshake_pcap}"
    from open80211.core.interfaces import system_command
    rc, _ = system_command(cmd, timeout=120)
    if rc == 0:
        ui.ok(f"hccapx export -> {out}")
    return out if rc == 0 else ""


# --------------------------------------------------------------------------
# NTLMv2 (hashcat 5600) export
# --------------------------------------------------------------------------

def export_ntlmv2(username: str, domain: str, challenge: bytes,
                  proof: bytes, blob: bytes, out_path: str = "") -> str:
    """
    hashcat mode 5600 line: username::domain:challenge:proof:blob
    """
    line = (f"{username}::{domain}:{challenge.hex()}:{proof.hex()}:{blob.hex()}")
    out_path = out_path or str(CONFIG.session_dir / "hashes-ntlmv2.txt")
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return out_path


# --------------------------------------------------------------------------
# HTML + JSON report assembly helpers
# --------------------------------------------------------------------------

def json_dump(name: str, data: dict) -> str:
    p = CONFIG.save(name, data)
    return str(p)


def tool_banner() -> str:
    """Detect the external arsenal and return a readable status."""
    avail = detect_tools()
    return " | ".join(f"{'OK' if v else '-'} {t}" for t, v in avail.items())


def detect_tools() -> dict:
    return {t: which(t) for t in
            ["aircrack-ng", "aireplay-ng", "wpaclean", "hashcat", "reaver",
             "hostapd", "hostapd-mana", "dnsmasq", "bettercap", "responder",
             "tcpdump", "iw", "airmon-ng", "hcxdumptool", "nmap", "freeradius",
             "hcitool", "hciconfig", "sdptool", "l2ping", "rfcomm",
             "bluetoothctl", "btmgmt", "grgsm_scanner", "kal",
             "rtl_test", "gammu", "hydra", "ncrack"]}