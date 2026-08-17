"""
IoT pentest suite.

Targets the protocols that power most smart-home / industrial / camera /
controller devices:

  * MQTT discovery  - find brokers, enumerate topics, inject + subscribe
  * UPnP / SSDP     - discover devices and exposed services
  * RTSP cameras    - probe streams, check weak auth
  * CoAP            - .well-known/core enumeration (RFC 7252)
  * Modbus/TCP      - industrial controller register read
  * HTTP devices    - banner grab + default-credential check
  * Discovery sweep - subnet-wide scan for common IoT ports

Pure-Python where possible; optional external bridges (nmap, onesixtyone,
mqtt client libs) are auto-detected and skipped when absent.
"""
import ipaddress
import json
import re
import socket
import struct
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core.interfaces import which
from open80211.core.targets import add_iot, add_cred, log_event

# Common IoT ports
IOT_PORTS = {
    1883: "MQTT",
    8883: "MQTT/TLS",
    5683: "CoAP",
    5684: "CoAP/TLS",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8554: "RTSP",
    502: "Modbus/TCP",
    47808: "BACnet",
    22: "SSH",
    23: "Telnet",
    1900: "SSDP/UPnP",
    4840: "OPC-UA",
    5000: "UPnP-SOAP",
    161: "SNMP",
    49152: "UPnP",
    8080: "HTTP",
}

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("root", "root"), ("root", "123456"),
    ("user", "user"), ("admin", "12345"), ("admin", "0000"),
    ("support", "support"), ("super", "super"), ("guest", "guest"),
]


def _tcp(host, port, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        return None


def _udp_send(host, port, payload, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        try:
            return s.recvfrom(4096)[0]
        except Exception:
            return None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Discovery sweep
# --------------------------------------------------------------------------

def discover_subnet(subnet: str, ports: list = None, timeout: float = 1.2) -> list:
    """Port-sweep a subnet for IoT services. Returns list of device dicts."""
    ports = ports or list(IOT_PORTS.keys())
    net = ipaddress.ip_network(subnet, strict=False)
    ui.section("IoT Discovery Sweep", f"{net} ports={len(ports)}")
    found = []
    lock = threading.Lock()
    hosts = list(net.hosts())[:254]

    def probe(ip):
        dev = {"ip": str(ip), "open": []}
        for port in ports:
            if _tcp(str(ip), port, 0.6):
                dev["open"].append(port)
        if dev["open"]:
            with lock:
                found.append(dev)

    threads = []
    for ip in hosts:
        t = threading.Thread(target=probe, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 64:
            for th in threads:
                th.join(timeout)
            threads = []
    for th in threads:
        th.join(timeout)

    add_iot(found)
    log_event("recon", f"IoT sweep found {len(found)} devices")
    ui.ok(f"Found {len(found)} devices with IoT ports.")
    return found


# --------------------------------------------------------------------------
# MQTT
# --------------------------------------------------------------------------

def mqtt_fingerprint(host: str, port: int = 1883) -> dict:
    """Connect and read the CONNACK + server features."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        ui.warn("paho-mqtt not installed (pip install paho-mqtt). Using raw socket.")
        return mqtt_raw_probe(host, port)
    info = {"host": host, "port": port, "connect": False}
    got = {}

    def on_connect(c, u, f, rc, p=None):
        got["rc"] = rc
        c.disconnect()

    try:
        c = mqtt.Client()
        if hasattr(c, "on_connect"):
            c.on_connect = on_connect
        c.connect(host, port, 5)
        c.loop_start()
        time.sleep(1.5)
        c.loop_stop()
        info["connect"] = True
        info["rc"] = got.get("rc")
    except Exception as e:
        info["error"] = str(e)
    return info


def mqtt_raw_probe(host: str, port: int = 1883) -> dict:
    """Raw MQTT CONNECT probe (no library)."""
    pkt = b"\x10" + bytes([0])  # CONNECT, len placeholder
    proto = b"\x00\x04MQTT\x04\x02\x00\x3c\x00"
    cli = b"open80211-probe"
    payload = proto + bytes([len(cli)]) + cli
    pkt = b"\x10" + bytes([len(payload)]) + payload
    s = _tcp(host, port, 4)
    if not s:
        return {"host": host, "connect": False, "error": "no connect"}
    try:
        s.sendall(pkt)
        resp = s.recv(64)
        if len(resp) >= 4 and resp[0] == 0x20:
            return {"host": host, "connect": True, "connack_rc": resp[3],
                    "session_present": resp[2] & 1}
    except Exception as e:
        return {"host": host, "connect": False, "error": str(e)}
    finally:
        s.close()
    return {"host": host, "connect": False}


def mqtt_enum_topics(host: str, port: int = 1883, wildcard: str = "#",
                     timeout: float = 10.0) -> list:
    """Subscribe to a wildcard and collect messages for `timeout` seconds."""
    topics = []
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        ui.warn("paho-mqtt required for topic enumeration (pip install paho-mqtt).")
        return topics
    ui.section("MQTT Topic Enumeration", f"{host}:{port} sub='{wildcard}'")

    def on_message(c, u, msg):
        topics.append({"topic": msg.topic, "payload": msg.payload[:200].decode(
            errors="replace")})

    try:
        c = mqtt.Client()
        c.on_message = on_message
        c.connect(host, port, 5)
        c.subscribe(wildcard)
        c.loop_start()
        time.sleep(timeout)
        c.loop_stop()
        c.disconnect()
    except Exception as e:
        ui.warn(str(e))
    if topics:
        ui.show_table("Captured MQTT Topics", ["Topic", "Payload"],
                      [[t["topic"], t["payload"]] for t in topics[:30]])
    else:
        ui.info("No messages captured (topic may be empty or ACL-protected).")
    return topics


def mqtt_inject(host: str, port: int, topic: str, payload: str) -> bool:
    """Publish arbitrary data to a topic (command injection on smart devices)."""
    try:
        import paho.mqtt.client as mqtt
        c = mqtt.Client()
        c.connect(host, port, 5)
        c.publish(topic, payload)
        c.disconnect()
        ui.ok(f"Published to {topic}: {payload}")
        return True
    except Exception as e:
        ui.error(str(e))
        return False


# --------------------------------------------------------------------------
# UPnP / SSDP
# --------------------------------------------------------------------------

SSDP_DISCOVER = ("M-SEARCH * HTTP/1.1\r\n"
                 "HOST: 239.255.255.250:1900\r\n"
                 "MAN: \"ssdp:discover\"\r\n"
                 "MX: 3\r\n"
                 "ST: ssdp:all\r\n\r\n").encode()


def upnp_scan(target: str = "239.255.255.250", timeout: float = 4.0) -> list:
    """SSDP discovery for UPnP devices."""
    ui.section("UPnP / SSDP Discovery", f"target={target}")
    devices = []
    seen = set()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(SSDP_DISCOVER, (target, 1900))
        while True:
            try:
                data, addr = s.recvfrom(8192)
                key = addr[0]
                if key in seen:
                    continue
                seen.add(key)
                header = data.decode(errors="replace")
                usn = [l for l in header.splitlines() if l.lower().startswith("usn:")]
                st = [l for l in header.splitlines() if l.lower().startswith("st:")]
                location = [l for l in header.splitlines()
                            if l.lower().startswith("location:")]
                devices.append({
                    "ip": addr[0], "usn": usn[0][4:].strip() if usn else "",
                    "st": st[0][3:].strip() if st else "",
                    "location": location[0][9:].strip() if location else "",
                })
            except socket.timeout:
                break
    except Exception as e:
        ui.warn(str(e))
    finally:
        s.close()
    ui.ok(f"Found {len(devices)} UPnP devices.")
    return devices


def upnp_fetch_device(device: dict) -> None:
    """Fetch and display the device description XML."""
    import urllib.request
    loc = device.get("location")
    if not loc:
        return
    try:
        resp = urllib.request.urlopen(loc, timeout=5).read().decode(errors="replace")
        ui.info(f"--- {loc} ---")
        print(resp[:2500])
    except Exception as e:
        ui.warn(str(e))


# --------------------------------------------------------------------------
# RTSP cameras
# --------------------------------------------------------------------------

def rtsp_probe(host: str, port: int = 554) -> dict:
    """Send OPTIONS / DESCRIBE and capture supported methods + public URL."""
    s = _tcp(host, port, 4)
    if not s:
        return {"host": host, "connect": False}
    info = {"host": host, "port": port, "connect": True}
    try:
        req = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(4096).decode(errors="replace")
        info["response"] = resp.strip()
        m = re.search(r"Public:\s*(.+)", resp, re.I)
        if m:
            info["methods"] = m.group(1).strip()
    except Exception as e:
        info["error"] = str(e)
    finally:
        s.close()
    return info


def rtsp_camera_scan(host: str, port: int = 554) -> None:
    """Enumerate common camera stream paths."""
    info = rtsp_probe(host, port)
    ui.show_table("RTSP", ["Field", "Value"],
                  [[k, v] for k, v in info.items()])
    if not info.get("connect"):
        return
    ui.info("Probing common stream URLs...")
    for path in ("/", "/live", "/live1", "/Streaming/Channels/101",
                 "/videoMain", "/cam/realmonitor?channel=1&subtype=0",
                 "/h264", "/live/ch0"):
        s = _tcp(host, port, 3)
        if not s:
            continue
        try:
            req = f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: 2\r\n\r\n"
            s.sendall(req.encode())
            resp = s.recv(2048).decode(errors="replace")
            code = resp.split(" ")[1] if " " in resp else "?"
            if code in ("200", "401", "403"):
                ui.info(f"  {path} -> {code}")
        except Exception:
            pass
        finally:
            s.close()


# --------------------------------------------------------------------------
# CoAP
# --------------------------------------------------------------------------

def coap_discover(host: str, port: int = 5683) -> dict:
    """RFC7252 GET /.well-known/core"""
    token = b"\x01\x02"
    payload = b"\x00\x01" + token  # Ver1, Type=CON, TKL=2, Code=GET
    uri = b"/.well-known/core"
    payload += b"\xbb" + bytes([len(uri)]) + uri
    resp = _udp_send(host, port, payload)
    if resp is None:
        return {"host": host, "resources": []}
    # decode: first 4 bytes header, then options
    return {"host": host, "resources": [resp[4:].decode(errors="replace")]}


# --------------------------------------------------------------------------
# Modbus/TCP
# --------------------------------------------------------------------------

def modbus_read(host: str, port: int = 502, unit: int = 1) -> dict:
    """Read a few holding registers (function 0x03)."""
    s = _tcp(host, port, 4)
    if not s:
        return {"host": host, "connect": False}
    try:
        # MBAP header + PDU (read holding regs 0..8)
        req = struct.pack(">HHHBBHHHH", 0x0001, 0, 6, unit, 0x03, 0, 8)
        s.sendall(req)
        resp = s.recv(256)
        if len(resp) >= 12:
            regs = struct.unpack(">8H", resp[10:26]) if len(resp) >= 26 else ()
            return {"host": host, "connect": True, "registers": list(regs),
                    "raw": resp.hex()}
        return {"host": host, "connect": True, "raw": resp.hex()}
    except Exception as e:
        return {"host": host, "connect": False, "error": str(e)}
    finally:
        s.close()


# --------------------------------------------------------------------------
# Default credential check
# --------------------------------------------------------------------------

def http_banner(host: str, port: int = 80) -> str:
    s = _tcp(host, port, 3)
    if not s:
        return ""
    try:
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
        resp = s.recv(2048).decode(errors="replace")
        s.close()
        return resp.strip()
    except Exception:
        return ""


def default_cred_check(host: str, port: int = 23) -> list:
    """Try default creds on telnet/HTTP-style logins."""
    results = []
    for user, pw in DEFAULT_CREDS:
        s = _tcp(host, port, 3)
        if not s:
            break
        try:
            s.settimeout(3)
            banner = s.recv(256).decode(errors="replace")
            s.sendall((user + "\n").encode())
            s.recv(256)
            s.sendall((pw + "\n").encode())
            resp = s.recv(512).decode(errors="replace")
            if any(k in resp.lower() for k in ("#", "$", "login:", ">", "~")):
                results.append({"user": user, "pass": pw, "banner": banner[:40]})
        except Exception:
            break
        finally:
            s.close()
    return results


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def iot_menu(iface: str = "") -> None:
    while True:
        choice = ui.menu("IoT Pentest Suite", [
            "Discovery sweep (subnet IoT port scan)",
            "MQTT - fingerprint broker",
            "MQTT - enumerate topics (subscribe #)",
            "MQTT - inject command",
            "UPnP / SSDP discovery",
            "RTSP camera probe",
            "CoAP discovery (.well-known/core)",
            "Modbus/TCP register read",
            "HTTP banner + default creds",
            "Save IoT findings to session",
        ])
        if choice == 0:
            return
        if choice == 1:
            subnet = ui.ask("Subnet (CIDR)", default="192.168.1.0/24")
            devs = discover_subnet(subnet)
            if devs:
                rows = [[d["ip"], ",".join(str(p) for p in d["open"]),
                         ";".join(IOT_PORTS[p] for p in d["open"])] for d in devs]
                ui.show_table("IoT Devices", ["IP", "Ports", "Services"], rows)
                CONFIG.save("iot_discovery", devs)
        elif choice == 2:
            host = ui.ask("MQTT broker IP")
            port = ui.ask_int("Port", default=1883)
            ui.show_table("MQTT Fingerprint", ["Field", "Value"],
                          [[k, v] for k, v in mqtt_fingerprint(host, port).items()])
        elif choice == 3:
            host = ui.ask("MQTT broker IP")
            port = ui.ask_int("Port", default=1883)
            dur = ui.ask_int("Listen seconds", default=10)
            topics = mqtt_enum_topics(host, port, "#", dur)
            if topics:
                CONFIG.save("iot_mqtt", {"host": host, "topics": topics})
        elif choice == 4:
            host = ui.ask("MQTT broker IP")
            port = ui.ask_int("Port", default=1883)
            topic = ui.ask("Topic")
            payload = ui.ask("Payload", default="ON")
            mqtt_inject(host, port, topic, payload)
        elif choice == 5:
            devs = upnp_scan()
            if devs:
                ui.show_table("UPnP Devices", ["IP", "ST", "Location"],
                              [[d["ip"], d["st"][:50], d["location"]] for d in devs])
                if ui.confirm("Fetch a device description?", default=False):
                    idx = ui.ask_int("Device #", default=1) - 1
                    if 0 <= idx < len(devs):
                        upnp_fetch_device(devs[idx])
        elif choice == 6:
            host = ui.ask("Camera IP")
            port = ui.ask_int("RTSP port", default=554)
            rtsp_camera_scan(host, port)
        elif choice == 7:
            host = ui.ask("CoAP host")
            port = ui.ask_int("Port", default=5683)
            info = coap_discover(host, port)
            ui.show_table("CoAP", ["Field", "Value"],
                          [[k, str(v)] for k, v in info.items()])
        elif choice == 8:
            host = ui.ask("Modbus device IP")
            port = ui.ask_int("Port", default=502)
            info = modbus_read(host, port)
            ui.show_table("Modbus", ["Field", "Value"],
                          [[k, str(v)] for k, v in info.items()])
        elif choice == 9:
            host = ui.ask("Device IP")
            port = ui.ask_int("Port (23 telnet / 80 http)", default=23)
            banner = http_banner(host, port)
            if banner:
                ui.info(f"Banner:\n{banner[:500]}")
            creds = default_cred_check(host, port)
            if creds:
                ui.warn(f"Default credentials found on {host}:{port}")
                ui.show_table("Weak Creds", ["User", "Pass"],
                              [[c["user"], c["pass"]] for c in creds])
                for c in creds:
                    add_cred({"protocol": f"IoT-Default:{port}",
                              "data": f"{host}:{port} {c['user']}:{c['pass']}",
                              "src": host})
            else:
                ui.info("No default creds accepted.")
        elif choice == 10:
            p = CONFIG.session_dir / "iot_mqtt.json"
            if p.exists():
                ui.info(f"Saved MQTT findings -> {p}")
            ui.info("IoT findings are stored automatically in the session dir.")