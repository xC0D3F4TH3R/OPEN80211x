"""
Global configuration and storage management for the suite.
All results (pcaps, logs, captured creds, reports) are organized
under a `results/` directory with per-run timestamps.
"""
import datetime
import json
import os
import platform
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

SUITE_ROOT = Path(__file__).resolve().parent.parent.parent  # repo root
RESULTS_DIR = SUITE_ROOT / "results"


@dataclass
class Config:
    """Runtime settings shared across modules."""
    interface: str = ""            # currently selected wireless interface
    channel: int = 0               # current working channel
    verbose: bool = False
    debug: bool = False
    forward_ip: bool = True        # ip_forward enabled when doing MITM
    results_dir: Path = RESULTS_DIR
    run_id: str = ""

    def __post_init__(self):
        if not self.run_id:
            self.run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir = self.results_dir / f"session-{self.run_id}"
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, data: dict, fmt: str = "json") -> Path:
        """Persist a result into the session folder."""
        if fmt == "json":
            p = self.session_dir / f"{name}.json"
            p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            return p
        elif fmt == "txt":
            p = self.session_dir / f"{name}.txt"
            p.write_text(str(data), encoding="utf-8")
            return p
        elif fmt == "pcap":
            p = self.session_dir / f"{name}.pcap"
            return p
        elif fmt == "html":
            p = self.session_dir / f"{name}.html"
            p.write_text(str(data), encoding="utf-8")
            return p
        raise ValueError(f"Unknown format {fmt}")


CONFIG = Config()


def bind_engagement():
    """Bind the global target store to the active session dir."""
    from open80211.core.targets import bind_targets
    bind_targets()


def is_root() -> bool:
    """True if running with sufficient privileges (root/admin)."""
    if os.name == "posix":
        return os.geteuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def os_banner() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def require_privileges(what: str = "this operation") -> bool:
    if is_root():
        return True
    from open80211.core.ui import warn, error
    warn(f"Running with limited privileges. {what} may fail.")
    return False


def check_platform(needs: str = "linux") -> bool:
    """Some features (monitor mode, injections) require Linux + wireless card."""
    from open80211.core.ui import warn
    if needs == "linux" and not is_linux():
        warn("This feature requires Linux with a wireless adapter capable of "
             "monitor mode and packet injection (e.g. Kali Linux / ALFA card).")
        return False
    return True


def set_ip_forward(on: bool) -> None:
    """Enable/disable kernel IP forwarding (needed for MITM routing)."""
    if not is_linux():
        return
    val = "1" if on else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
    except Exception:
        from open80211.core.ui import warn
        warn("Could not toggle IP forwarding. Run as root or set manually.")