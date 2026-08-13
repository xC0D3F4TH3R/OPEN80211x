#!/usr/bin/env python3
"""
open80211 - Advanced Wireless Penetration Testing Suite

Usage:
    python open80211.py               interactive menu
    python open80211.py --scan        quick AP scan
    python open80211.py --version
    python open80211.py --help
"""
import argparse
import sys
import threading

from open80211 import __version__
from open80211.core import ui
from open80211.core.config import CONFIG, is_root, is_linux
from open80211.core.interfaces import list_interfaces, set_monitor_mode, set_channel


def cmd_scan(args) -> None:
    """One-shot network scan without entering the full menu."""
    from open80211.modules.recon import scan_networks, show_networks
    iface = args.interface or (list_interfaces() and list_interfaces()[0]["name"]) or ""
    if not iface:
        ui.error("No interface available.")
        return
    if not is_linux():
        ui.warn("Full 802.11 scanning requires Linux + monitor mode. "
                "Falling back to best-effort managed capture.")
    if args.monitor and is_linux():
        set_monitor_mode(iface, True)
    if args.channel:
        set_channel(iface, args.channel)
    nets = scan_networks(iface, duration=args.duration)
    show_networks(nets)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="open80211",
        description="Advanced wireless penetration testing suite (ethical use only).")
    parser.add_argument("--version", action="version", version=f"open80211 {__version__}")
    parser.add_argument("-i", "--interface", help="wireless interface to use")
    parser.add_argument("--scan", action="store_true", help="run a quick AP scan")
    parser.add_argument("--monitor", action="store_true", help="enable monitor mode before scan")
    parser.add_argument("-c", "--channel", type=int, help="lock channel before scan")
    parser.add_argument("-d", "--duration", type=float, default=10.0,
                        help="scan duration in seconds")
    parser.add_argument("--debug", action="store_true", help="verbose debug output")
    args = parser.parse_args()

    CONFIG.debug = args.debug
    if args.debug:
        sys.argv.append("--debug")
    if args.interface:
        CONFIG.interface = args.interface

    if args.scan:
        cmd_scan(args)
        return

    from open80211.menu import main_menu
    main_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        ui.info("Interrupted. Exiting.")
        sys.exit(0)
    except Exception as e:  # noqa: BLE001
        ui.error(f"Unexpected error: {e}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)