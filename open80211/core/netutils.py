"""
Networking helpers: MAC/IP math, and the protocol DECODER used across
the capture and MITM modules to make every packet human-readable.
"""
from __future__ import annotations

import re
import socket
import struct
import time

try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, LLC, SNAP, Ether
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
except Exception:  # pragma: no cover - import errors surface at runtime
    pass


# --------------------------------------------------------------------------
# MAC / IP helpers
# --------------------------------------------------------------------------

def norm_mac(mac: str) -> str:
    """Normalize any MAC format to aa:bb:cc:dd:ee:ff."""
    m = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(m) != 12:
        return str(mac).lower()
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)).lower()


def mac2int(mac: str) -> int:
    return int(norm_mac(mac).replace(":", ""), 16)


def int2mac(i: int) -> str:
    return ":".join(f"{(i >> s) & 0xff:02x}" for s in range(40, -8, -8))


def ip2int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int2ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", i & 0xFFFFFFFF))


def is_broadcast_mac(mac: str) -> bool:
    return norm_mac(mac) == "ff:ff:ff:ff:ff:ff"


def get_oui(mac: str) -> str:
    """Vendor prefix (24 bits) of a MAC."""
    return norm_mac(mac)[:8]


# --------------------------------------------------------------------------
# Frequency / channel helpers
# --------------------------------------------------------------------------

FREQ_CHANNEL = {2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7,
                2447: 8, 2452: 9, 2457: 10, 2462: 11, 2467: 12, 2472: 13,
                2484: 14, 5180: 36, 5200: 40, 5220: 44, 5240: 48, 5260: 52,
                5280: 56, 5300: 60, 5320: 64, 5500: 100, 5520: 104, 5540: 108,
                5560: 112, 5580: 116, 5600: 120, 5620: 124, 5640: 128, 5660: 132,
                5680: 136, 5700: 140, 5745: 149, 5765: 153, 5785: 157, 5805: 161,
                5825: 165}

freq_to_channel = FREQ_CHANNEL.get

CHANNEL_FREQ = {v: k for k, v in FREQ_CHANNEL.items()}
channel_to_freq = CHANNEL_FREQ.get


# --------------------------------------------------------------------------
# Protocol name detection
# --------------------------------------------------------------------------

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1900: "SSDP", 2049: "NFS",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 6667: "IRC",
    7001: "WebLogic", 8000: "AltHTTP", 8009: "AJP", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "AltService", 9200: "Elasticsearch",
    27017: "MongoDB", 47001: "WinRM",
}


def guess_protocol(src_port: int, dst_port: int) -> str:
    """Best-effort protocol name from ports."""
    if dst_port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[dst_port]
    if src_port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[src_port]
    return "TCP" if dst_port else "UDP"


def encryption_info(pkt) -> str:
    """Decode WPA/WPA2/WPA3/OWE ciphers + AKM from a beacon/probe-resp."""
    if not hasattr(pkt, "cap"):
        return "Open"
    if not bool(pkt.cap & 0x10):
        return "Open"
    rsn = None
    for elt in _elts(pkt):
        if elt.ID == 48:
            rsn = elt
        if elt.ID == 221 and elt.info[:4] == b"\x00P\xf2\x01":
            rsn = elt
    if rsn is None:
        return "WEP"
    data = rsn.info
    try:
        vendor = data[:4] == b"\x00P\xf2\x01"
        if vendor:
            body = data[4:]  # skip OUI + type
        else:
            body = data[2:]  # skip RSN version
        # layout: group(4) | pair_count(2) | pairs(n*4) | akm_count(2) | akms(m*4)
        n = struct.unpack(">H", body[4:6])[0]
        ciphers = body[6:6 + n * 4]
        cipher_names = []
        for i in range(n):
            c = ciphers[i * 4:i * 4 + 4]
            if c in (b"\x00\x0f\xac\x04", b"\x00P\xf2\x04"):
                cipher_names.append("CCMP")
            elif c in (b"\x00\x0f\xac\x02", b"\x00P\xf2\x02"):
                cipher_names.append("TKIP")
            elif c == b"\x00\x0f\xac\x05":
                cipher_names.append("GCMP")
        off = 6 + n * 4
        if off + 2 > len(body):
            return "WPA2"
        n_akm = struct.unpack(">H", body[off:off + 2])[0]
        akms = body[off + 2:off + 2 + n_akm * 4]
        akm_names = []
        for i in range(n_akm):
            a = akms[i * 4:i * 4 + 4]
            if a == b"\x00\x0f\xac\x08":
                akm_names.append("SAE")
            elif a == b"\x00\x0f\xac\x09":
                akm_names.append("FT-SAE")
            elif a == b"\x00\x0f\xac\x0c":
                akm_names.append("SAE")
            elif a == b"\x00\x0f\xac\x12":
                akm_names.append("OWE")
            elif a in (b"\x00\x0f\xac\x02", b"\x00P\xf2\x02"):
                akm_names.append("PSK")
            elif a in (b"\x00\x0f\xac\x01", b"\x00P\xf2\x01"):
                akm_names.append("EAP")
        proto = "WPA3" if "SAE" in akm_names else \
            "OWE" if "OWE" in akm_names else \
            ("WPA" if vendor else "WPA2")
        enc = "/".join(cipher_names) if cipher_names else "?"
        akm = "/".join(set(akm_names)) if akm_names else "?"
        return f"{proto}-{enc} ({akm})"
    except Exception:
        return "WPA?"


def _elts(pkt):
    """Iterate 802.11 information elements."""
    out = []
    e = pkt.getlayer(Dot11Elt)
    while e is not None and isinstance(e, Dot11Elt):
        out.append(e)
        e = e.payload
    return out


def ssid_of(pkt) -> str:
    for elt in _elts(pkt):
        if elt.ID == 0:
            return elt.info.decode(errors="replace")
    return ""


# --------------------------------------------------------------------------
# Human-readable packet decode (the tcpdump-style summary)
# --------------------------------------------------------------------------

def decode_packet(pkt) -> str:
    """Return a one-line human description of any captured packet."""
    try:
        if pkt.haslayer(RadioTap):
            layers = pkt.getlayer(RadioTap).payload
        else:
            layers = pkt
        if layers.haslayer(Dot11):
            return _decode_80211(pkt)
        if layers.haslayer(ARP):
            return _decode_arp(layers)
        if layers.haslayer(IPv6):
            return _decode_ipv6(layers)
        if layers.haslayer(IP):
            return _decode_ip(layers)
    except Exception:
        pass
    return f"Unknown/L2 ({type(pkt).__name__})"


def _decode_80211(pkt) -> str:
    rt = pkt.getlayer(RadioTap)
    dbm = ""
    if rt is not None and hasattr(rt, "dBm_AntSignal"):
        dbm = f" sig={rt.dBm_AntSignal}dBm"
    l = pkt.getlayer(Dot11)
    if not l:
        return ""
    fc_type, fc_sub = l.type, l.subtype
    src, dst, bssid = l.addr2 or "", l.addr1 or "", l.addr3 or ""
    tag = {0: "ASSOC-REQ", 1: "ASSOC-RESP", 2: "REASSOC-REQ", 4: "PROBE-REQ",
           5: "PROBE-RESP", 8: "BEACON", 10: "DEAUTH", 11: "AUTH", 12: "ACTION",
           13: "ACTION-NOACK"}.get(fc_sub, f"MGMT:{fc_sub}")
    if fc_type == 0:
        if fc_sub == 8:
            ssid = ssid_of(pkt)
            enc = encryption_info(pkt)
            return f"[802.11] BEACON {bssid} SSID='{ssid}' {enc}{dbm}"
        if fc_sub == 5:
            return f"[802.11] PROBE-RESP {bssid} SSID='{ssid_of(pkt)}'{dbm}"
        if fc_sub == 4:
            return f"[802.11] PROBE-REQ from {src} for '{ssid_of(pkt)}'{dbm}"
        if fc_sub == 10:
            return f"[802.11] DEAUTH {bssid} -> {dst}{dbm}"
        if fc_sub == 11:
            return f"[802.11] AUTH {bssid} -> {dst}{dbm}"
        return f"[802.11] {tag} {src}->{dst}{dbm}"
    if fc_type == 2:
        return f"[802.11] DATA {src}->{dst} {bssid}{dbm}"
    if fc_type == 1:
        return f"[802.11] CTRL {src}->{dst}{dbm}"
    return f"[802.11] TYPE{fc_type}/{fc_sub} {src}->{dst}{dbm}"


def _decode_arp(pkt) -> str:
    op = "REQ" if pkt.op == 1 else "REPLY"
    return f"ARP {op} who-has {pkt.pdst} tell {pkt.psrc} ({pkt.hwsrc}->{pkt.hwdst})"


def _decode_ip(pkt) -> str:
    ip = pkt.getlayer(IP)
    ttl = f" ttl={ip.ttl}"
    if ip.proto == 1 and pkt.haslayer(ICMP):
        ic = pkt.getlayer(ICMP)
        return f"ICMP {ip.src}->{ip.dst} type={ic.type} code={ic.code}{ttl}"
    if ip.proto in (6, 17):
        proto = "TCP" if ip.proto == 6 else "UDP"
        layer = pkt.getlayer(TCP) if ip.proto == 6 else pkt.getlayer(UDP)
        sport, dport = layer.sport, layer.dport
        name = guess_protocol(sport, dport)
        flags = ""
        extra = ""
        if ip.proto == 6:
            flags = _tcp_flags(layer.flags)
        if pkt.haslayer(Raw):
            pl = bytes(pkt.getlayer(Raw).load)
            extra = f" len={len(pl)} {_payload_teaser(pl)}"
        return f"{name} {ip.src}:{sport}->{ip.dst}:{dport} {flags}{extra}{ttl}"
    return f"IP-proto{ip.proto} {ip.src}->{ip.dst}{ttl}"


def _decode_ipv6(pkt) -> str:
    v6 = pkt.getlayer(IPv6)
    if pkt.haslayer(UDP):
        u = pkt.getlayer(UDP)
        return f"IPv6-UDP {v6.src}->{v6.dst} ports {u.sport}/{u.dport}"
    return f"IPv6 {v6.src}->{v6.dst}"


def _tcp_flags(flags) -> str:
    s = str(flags)
    return f"[{s}]" if s else ""


def _payload_teaser(pl: bytes, n: int = 40) -> str:
    """First printable chunk of a payload for display."""
    txt = ""
    for b in pl[:n]:
        if 32 <= b < 127:
            txt += chr(b)
        else:
            txt += "."
    return f"'{txt}'"


# --------------------------------------------------------------------------
# Deep protocol extraction for MITM / analysis
# --------------------------------------------------------------------------

def extract_layers(pkt) -> dict:
    """Return a dict describing the interesting fields of a packet."""
    info = {"time": time.time(), "summary": decode_packet(pkt)}
    try:
        if pkt.haslayer(IP):
            ip = pkt.getlayer(IP)
            info["src_ip"], info["dst_ip"] = ip.src, ip.dst
            info["proto"] = "ICMP" if ip.proto == 1 else ("TCP" if ip.proto == 6 else
                                                          ("UDP" if ip.proto == 17 else ip.proto))
            if pkt.haslayer(TCP):
                t = pkt.getlayer(TCP)
                info.update(sport=t.sport, dport=t.dport,
                            flags=str(t.flags), seq=t.seq, ack=t.ack)
            elif pkt.haslayer(UDP):
                u = pkt.getlayer(UDP)
                info.update(sport=u.sport, dport=u.dport)
        if pkt.haslayer(ARP):
            a = pkt.getlayer(ARP)
            info.update(op=a.op, psrc=a.psrc, pdst=a.pdst,
                        hwsrc=a.hwsrc, hwdst=a.hwdst)
        if pkt.haslayer(Dot11):
            d = pkt.getlayer(Dot11)
            info["mac_src"] = d.addr2
            info["mac_dst"] = d.addr1
    except Exception:
        pass
    return info


def raw_payload(pkt) -> bytes:
    """Concatenated raw payload bytes of a packet."""
    if pkt.haslayer(Raw):
        return bytes(pkt.getlayer(Raw).load)
    return b""


def parse_http(payload: bytes) -> dict | None:
    """Naive HTTP request/response parser. Returns dict or None."""
    if not payload:
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    if not head:
        return None
    try:
        lines = head.decode(errors="replace").split("\r\n")
    except Exception:
        return None
    first = lines[0]
    if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
                         "PATCH ", "CONNECT ")):
        parts = first.split(" ")
        if len(parts) >= 3:
            url = parts[1]
            full = f"{url}"
            host = ""
            cookies = {}
            user_agent = ""
            for l in lines[1:]:
                if l.lower().startswith("host:"):
                    host = l.split(":", 1)[1].strip()
                elif l.lower().startswith("cookie:"):
                    for c in l.split(":", 1)[1].strip().split(";"):
                        c = c.strip()
                        if "=" in c:
                            k, v = c.split("=", 1)
                            cookies[k.strip()] = v.strip()
                elif l.lower().startswith("user-agent:"):
                    user_agent = l.split(":", 1)[1].strip()
            return {"type": "request", "method": parts[0], "url": url,
                    "host": host, "cookies": cookies, "user_agent": user_agent,
                    "body": body.decode(errors="replace")[:2000]}
    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        code = parts[1] if len(parts) > 1 else "?"
        return {"type": "response", "status": code,
                "reason": parts[2] if len(parts) > 2 else "",
                "body": body.decode(errors="replace")[:2000]}
    return None


def parse_dns_query(payload: bytes) -> dict | None:
    """Parse a DNS query payload -> {'qname', 'qtype'} or None."""
    if len(payload) < 12:
        return None
    try:
        flags = struct.unpack(">H", payload[2:4])[0]
        qdcount = struct.unpack(">H", payload[4:6])[0]
        if qdcount == 0 or flags & 0x8000:
            return None  # response or malformed
        idx = 12
        labels = []
        while True:
            ln = payload[idx]
            if ln == 0:
                idx += 1
                break
            if ln & 0xC0 == 0xC0:
                idx += 2
                break
            idx += 1
            labels.append(payload[idx:idx + ln].decode(errors="replace"))
            idx += ln
        qtype = struct.unpack(">H", payload[idx:idx + 2])[0]
        return {"qname": ".".join(labels), "qtype": qtype}
    except Exception:
        return None


def dns_query_info(pkt) -> dict | None:
    """DNS query info from a live packet (handles scapy DNS layer + raw bytes)."""
    try:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            if dns.qr == 0 and dns.qd:
                qd = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
                name = qd.qname.decode(errors="replace").rstrip(".")
                return {"qname": name, "qtype": qd.qtype}
    except Exception:
        pass
    return parse_dns_query(raw_payload(pkt))


CRED_PROTOCOLS = {
    "FTP": (21,),
    "Telnet": (23,),
    "SMTP": (25, 465, 587),
    "HTTP": (80, 8000, 8080, 8888),
    "POP3": (110,),
    "IMAP": (143,),
}


def extract_credentials(pkt) -> list:
    """Extract plaintext credentials from a packet. Returns list of dicts."""
    found = []
    pl = raw_payload(pkt)
    if not pl:
        return found
    try:
        if pkt.haslayer(TCP):
            t = pkt.getlayer(TCP)
            dport, sport = t.dport, t.sport
        else:
            return found
    except Exception:
        return found

    text = pl.decode(errors="replace")
    ports = set([dport, sport])

    # HTTP Basic / form
    if 80 in ports or dport in (8000, 8080, 8888):
        http = parse_http(pl)
        if http and http.get("type") == "request":
            if "authorization" in text.lower() and "basic" in text.lower():
                m = re.search(r"Authorization: Basic\s+(\S+)", text, re.I)
                if m:
                    import base64
                    try:
                        cred = base64.b64decode(m.group(1)).decode(errors="replace")
                        found.append({"protocol": "HTTP-Basic", "data": cred,
                                      "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
                    except Exception:
                        pass
            for pat in ("user=", "username=", "login=", "user_name=",
                        "uname=", "email=", "pass=", "password=", "passwd=",
                        "pwd=", "key=", "pin=", "otp="):
                for m in re.finditer(re.escape(pat) + r"([^&\s\"']+)", text, re.I):
                    key = m.group(0).split("=")[0]
                    if key.lower() not in ("key=",):
                        found.append({"protocol": "HTTP-Form",
                                      "data": m.group(0),
                                      "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
            if http.get("cookies"):
                for k, v in http["cookies"].items():
                    found.append({"protocol": "HTTP-Cookie", "data": f"{k}={v}",
                                  "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})

    # FTP
    if 21 in ports:
        if "PASS " in text or "USER " in text:
            for m in re.finditer(r"(USER|PASS)\s+(\S+)", text, re.I):
                found.append({"protocol": "FTP", "data": m.group(0),
                              "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
    # Telnet / SMTP / POP3 / IMAP basic patterns
    if 23 in ports:
        for m in re.finditer(r"(login|password)[=:\s]+(\S+)", text, re.I):
            found.append({"protocol": "Telnet", "data": m.group(0),
                          "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
    if 25 in ports or 587 in ports:
        for m in re.finditer(r"(AUTH LOGIN|USER|PASS)\s+(\S+)", text, re.I):
            found.append({"protocol": "SMTP", "data": m.group(0),
                          "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
    if 110 in ports:
        for m in re.finditer(r"(USER|PASS)\s+(\S+)", text, re.I):
            found.append({"protocol": "POP3", "data": m.group(0),
                          "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
    if 143 in ports:
        for m in re.finditer(r"(LOGIN)\s+(\S+)\s+(\S+)", text, re.I):
            found.append({"protocol": "IMAP", "data": m.group(0),
                          "src": pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"})
    return found


def tls_metadata(pkt) -> dict | None:
    """Extract SNI host from a TLS ClientHello. Handles real ClientHello layout."""
    pl = raw_payload(pkt)
    if not pl or len(pl) < 5 or pl[0] != 0x16:
        return None
    try:
        rec_len = struct.unpack(">H", pl[3:5])[0]
        if rec_len < 1 or rec_len > len(pl) - 5:
            return None
        hand = pl[5:5 + rec_len]
        if hand[0] != 0x01:  # handshake type = ClientHello
            return None
        hs_len = int.from_bytes(hand[1:4], "big")
        body = hand[4:4 + hs_len]
        if len(body) < 35:
            return None
        sid_len = body[34]  # version(2) + random(32)
        idx = 35 + sid_len
        if idx + 2 > len(body):
            return None
        cs_len = struct.unpack(">H", body[idx:idx + 2])[0]
        idx += 2 + cs_len
        if idx >= len(body):
            return None
        comp_len = body[idx]
        idx += 1 + comp_len
        if idx + 2 > len(body):
            return None
        ext_len = struct.unpack(">H", body[idx:idx + 2])[0]
        idx += 2
        end = min(idx + ext_len, len(body))
        while idx + 4 <= end:
            etype = struct.unpack(">H", body[idx:idx + 2])[0]
            elen = struct.unpack(">H", body[idx + 2:idx + 4])[0]
            idx += 4
            if idx + elen > len(body):
                break
            if etype == 0 and elen >= 5:  # SNI extension
                name_len = struct.unpack(">H", body[idx + 3:idx + 5])[0]
                return {"sni": body[idx + 5:idx + 5 + name_len].decode(errors="replace")}
            idx += elen
    except Exception:
        pass
    return None