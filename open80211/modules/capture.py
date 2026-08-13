"""
Packet capture module (tcpdump-style live sniffer).

Captures live traffic, decodes every packet into a readable line,
supports BPF-ish keyword filters, live statistics, hex dumps, and
saving to pcap. Works in both managed (Ethernet/WiFi) and monitor mode.
"""
import time
from collections import defaultdict

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core import netutils as nu

try:
    from scapy.all import sniff, wrpcap, Dot11
except Exception:
    pass


def build_filter(filters: dict) -> str:
    """Compose a scapy filter string from user selections."""
    parts = []
    if filters.get("proto"):
        parts.append(filters["proto"].lower())
    if filters.get("host"):
        parts.append(f"host {filters['host']}")
    if filters.get("port"):
        parts.append(f"port {filters['port']}")
    return " and ".join(parts)


def run_capture(iface: str, store: bool = True, live_decoder: bool = True,
                duration: float = 0.0, cap_filter: str = "",
                decode_80211: bool = False) -> str:
    """
    Capture packets from `iface`. Returns path to saved pcap (if store).
    Ctrl+C stops early; a live summary is printed.
    """
    ui.section("Live Capture", f"iface={iface} store={store} filter='{cap_filter or 'all'}'")
    saved = CONFIG.save(f"capture-{int(time.time())}", {}, "pcap")
    pkts = []
    counters = defaultdict(int)
    start = time.time()
    ui.info("Capturing... press Ctrl+C to stop.")
    try:
        if store:
            sniff(iface=iface, prn=lambda p: _on_packet(p, pkts, counters, live_decoder),
                  store=True, timeout=duration or None, filter=cap_filter or None)
        else:
            sniff(iface=iface, prn=lambda p: _on_packet(p, pkts, counters, live_decoder),
                  store=False, timeout=duration or None, filter=cap_filter or None)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        ui.error(f"Capture failed: {e}")
    elapsed = time.time() - start
    if store:
        try:
            wrpcap(str(saved), pkts)
            ui.ok(f"Saved {len(pkts)} packets -> {saved}")
        except Exception as e:
            ui.error(f"Could not save pcap: {e}")
    ui.show_table("Capture Summary", ["Metric", "Value"], [
        ["Packets", len(pkts)],
        ["Duration", f"{elapsed:.1f}s"],
        ["Rate", f"{len(pkts)/max(elapsed,0.001):.1f} pkt/s"],
        ["Unique sources", len({nu.extract_layers(p).get('src_ip','') for p in pkts})],
    ])
    return str(saved) if store else ""


def _on_packet(pkt, pkts, counters, live_decoder):
    pkts.append(pkt)
    line = nu.decode_packet(pkt)
    key = line.split(" ")[0].strip("[]") if line else "?"
    counters[key] += 1
    if live_decoder:
        ui.debug(line)
        # periodic summary
        if len(pkts) % 50 == 0:
            top = sorted(counters.items(), key=lambda x: -x[1])[:5]
            ui.info(f"[{len(pkts)} packets] " + " | ".join(f"{k}:{v}" for k, v in top))


def interactive_capture(iface: str) -> None:
    """Menu-driven capture session."""
    while True:
        choice = ui.menu("Capture / Tcpdump", [
            "Start live capture (store to pcap)",
            "Start live capture (no store, fast)",
            "Capture on specific port",
            "Capture specific protocol (arp/tcp/udp/icmp/dhcp/dns)",
            "Capture WiFi 802.11 (monitor mode)",
            "Hex-dump last captured packet (run capture first)",
        ])
        if choice == 0:
            return
        if choice == 1:
            run_capture(iface)
        elif choice == 2:
            run_capture(iface, store=False)
        elif choice == 3:
            port = ui.ask("Port", default="80")
            run_capture(iface, cap_filter=f"port {port}")
        elif choice == 4:
            proto = ui.ask("Protocol", default="tcp")
            run_capture(iface, cap_filter=proto)
        elif choice == 5:
            run_capture(iface, decode_80211=True)
        elif choice == 6:
            pcap = ui.ask("Path to pcap file (or blank to skip)", default=str(CONFIG.session_dir))
            ui.info("Hex dump available via Analysis > Inspect pcap")