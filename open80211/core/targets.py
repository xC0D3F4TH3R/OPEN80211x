"""
Target Registry - the shared intelligence store of the engagement.

Every module writes what it learns into TARGETS (APs, hosts, clients,
Bluetooth devices, IoT devices, captured credentials) and every attack
can pick a target instead of typing it. This is what turns a pile of
menus into a *workflow*: you discover once, then attack from a picker.

All data is persisted per-session to `results/session-<id>/targets.json`
so an interrupted engagement can be resumed later.
"""
import json
import time
from pathlib import Path

from open80211.core.config import CONFIG


class TargetStore:
    """Thread-safe-ish shared store for every target the engagement knows."""

    def __init__(self):
        self.aps = []          # {bssid, ssid, channel, enc, signal, clients[]}
        self.hosts = []        # {ip, mac, vendor, ports[], services{}}
        self.clients = []      # {mac, probes[], associated_to, signal}
        self.bluetooth = []    # {addr, name, rssi, type}
        self.iot = []          # {ip, open[], services[]}
        self.cellular = {}     # identity dict
        self.creds = []        # {protocol, data, src, time}
        self.notes = []        # {time, text}
        self.timeline = []     # {time, action, detail}
        self._path = None

    # --- persistence ----------------------------------------------------

    def bind(self, path: Path):
        self._path = path
        self.load()

    def load(self):
        if self._path and self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                for k in ("aps", "hosts", "clients", "bluetooth", "iot",
                          "creds", "notes", "timeline"):
                    if isinstance(data.get(k), list):
                        setattr(self, k, data[k])
                if isinstance(data.get("cellular"), dict):
                    self.cellular = data["cellular"]
            except Exception:
                pass

    def save(self):
        if not self._path:
            return
        data = {k: getattr(self, k) for k in
                ("aps", "hosts", "clients", "bluetooth", "iot", "cellular",
                 "creds", "notes", "timeline")}
        try:
            self._path.write_text(json.dumps(data, indent=2, default=str),
                                  encoding="utf-8")
        except Exception:
            pass

    # --- timeline -------------------------------------------------------

    def log(self, action: str, detail: str = ""):
        self.timeline.append({"time": time.time(), "action": action,
                              "detail": detail})
        self.save()

    def add_note(self, text: str):
        self.notes.append({"time": time.time(), "text": text})
        self.save()

    # --- upserts --------------------------------------------------------

    def add_ap(self, ap: dict):
        bssid = str(ap.get("bssid", "")).lower()
        for i, existing in enumerate(self.aps):
            if existing.get("bssid", "").lower() == bssid:
                merged = dict(existing)
                merged.update({k: v for k, v in ap.items() if v})
                self.aps[i] = merged
                self.save()
                return merged
        self.aps.append(ap)
        self.save()
        return ap

    def add_aps(self, aps: list):
        for ap in aps:
            self.add_ap(ap)

    def add_host(self, host: dict):
        ip = str(host.get("ip", ""))
        for i, existing in enumerate(self.hosts):
            if existing.get("ip") == ip:
                merged = dict(existing)
                merged.update({k: v for k, v in host.items() if v})
                if host.get("open"):
                    ports = set(existing.get("open", [])) | set(host["open"])
                    merged["open"] = sorted(ports)
                self.hosts[i] = merged
                self.save()
                return merged
        self.hosts.append(host)
        self.save()
        return host

    def add_clients(self, clients: list):
        known = {c["mac"].lower(): c for c in self.clients}
        for c in clients:
            mac = c.get("mac", "").lower()
            if mac in known:
                known[mac].update(c)
            else:
                known[mac] = c
                self.clients.append(c)
        self.save()

    def add_bluetooth(self, devices: list):
        known = {d["addr"].lower(): d for d in self.bluetooth}
        for d in devices:
            addr = d.get("addr", "").lower()
            if addr in known:
                known[addr].update(d)
            else:
                known[addr] = d
                self.bluetooth.append(d)
        self.save()

    def add_iot(self, devices: list):
        known = {d["ip"]: d for d in self.iot}
        for d in devices:
            ip = d.get("ip", "")
            if ip in known:
                ports = set(known[ip].get("open", [])) | set(d.get("open", []))
                known[ip].update(d)
                known[ip]["open"] = sorted(ports)
            else:
                self.iot.append(d)
        self.save()

    def add_cred(self, cred: dict):
        self.creds.append(cred)
        self.save()

    # --- pickers --------------------------------------------------------

    def pick_ap(self, prompt: str = "Select target AP") -> dict | None:
        from open80211.core import ui
        if not self.aps:
            ui.warn("No APs in registry. Run Recon first.")
            return None
        rows = [[a["bssid"], a.get("ssid", ""), a.get("channel", "?"),
                 a.get("enc", "?"), f"{a.get('signal', '?')}dBm",
                 len(a.get("clients", []))] for a in self.aps]
        ui.show_table("Target APs", ["BSSID", "SSID", "CH", "Enc", "Sig", "Cli"],
                      rows)
        idx = ui.ask_int(f"{prompt} [1-{len(self.aps)}]", default=1)
        if not (1 <= idx <= len(self.aps)):
            return None
        return self.aps[idx - 1]

    def pick_host(self, prompt: str = "Select target host") -> dict | None:
        from open80211.core import ui
        if not self.hosts:
            ui.warn("No hosts in registry. Run LAN discovery first.")
            return None
        rows = [[h["ip"], h.get("mac", ""), h.get("vendor", ""),
                 len(h.get("open", []))] for h in self.hosts]
        ui.show_table("Target Hosts", ["IP", "MAC", "Vendor", "Open ports"],
                      rows)
        idx = ui.ask_int(f"{prompt} [1-{len(self.hosts)}]", default=1)
        if not (1 <= idx <= len(self.hosts)):
            return None
        return self.hosts[idx - 1]

    def pick_bluetooth(self, prompt: str = "Select BT target") -> dict | None:
        from open80211.core import ui
        if not self.bluetooth:
            ui.warn("No Bluetooth devices in registry. Scan first.")
            return None
        rows = [[d["addr"], d.get("name", ""), d.get("rssi", "?")]
                for d in self.bluetooth]
        ui.show_table("Bluetooth Targets", ["Addr", "Name", "RSSI"], rows)
        idx = ui.ask_int(f"{prompt} [1-{len(self.bluetooth)}]", default=1)
        if not (1 <= idx <= len(self.bluetooth)):
            return None
        return self.bluetooth[idx - 1]

    # --- overview -------------------------------------------------------

    def summary(self) -> list:
        return [
            ["Access points", len(self.aps)],
            ["Hosts", len(self.hosts)],
            ["Clients (WiFi)", len(self.clients)],
            ["Bluetooth devices", len(self.bluetooth)],
            ["IoT devices", len(self.iot)],
            ["Credentials captured", len(self.creds)],
            ["Notes", len(self.notes)],
            ["Timeline events", len(self.timeline)],
        ]


# Global singleton bound to the current session
TARGETS = TargetStore()


def bind_targets():
    TARGETS.bind(CONFIG.session_dir / "targets.json")


# convenience importers keep call sites clean
def add_ap(ap: dict): TARGETS.add_ap(ap)
def add_aps(aps: list): TARGETS.add_aps(aps)
def add_host(host: dict): TARGETS.add_host(host)
def add_clients(clients: list): TARGETS.add_clients(clients)
def add_bluetooth(devices: list): TARGETS.add_bluetooth(devices)
def add_iot(devices: list): TARGETS.add_iot(devices)
def add_cred(cred: dict): TARGETS.add_cred(cred)
def log_event(action: str, detail: str = ""): TARGETS.log(action, detail)
def add_note(text: str): TARGETS.add_note(text)
def pick_ap(prompt="Select target AP"): return TARGETS.pick_ap(prompt)
def pick_host(prompt="Select target host"): return TARGETS.pick_host(prompt)
def pick_bluetooth(prompt="Select BT target"): return TARGETS.pick_bluetooth(prompt)