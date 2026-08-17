"""
Cellular / SIM / cell-tower attack suite.

Works with a USB GSM/UMTS/LTE modem or any AT-capable device (droid/phone,
Huawei/Quectel sticks). Provides:

  * Modem discovery      - enumerate serial ports / USB modems
  * AT command console   - raw interactive AT session
  * SIM identity         - ICCID, IMSI, MSISDN, operator, SPN
  * Network registration - RAT, operator, LAC/CID (cell tower you are on)
  * Neighbour cells      - nearby cell towers via AT+CNETSCAN / AT+CCED
  * SMS management       - read / send / wipe SMS (SIM card)
  * USSD                 - send USSD codes (*#06#, balance, etc.)
  * IMSI-catcher check   - monitor sudden LAC/CID/operator changes
  * External bridges     - gr-gsm (GSM sniffing), kalibrate, osmocom

Every operation is best-effort and shows raw AT responses so you can
always see what the modem returned.
"""
import glob
import re
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG, is_linux
from open80211.core.interfaces import which


def _serial():
    """Lazy pyserial import so the rest of the suite works without it."""
    try:
        import serial
        return serial
    except ImportError:
        return None

# --------------------------------------------------------------------------
# Port / modem discovery
# --------------------------------------------------------------------------

def find_modems() -> list:
    """Enumerate likely serial modem devices."""
    candidates = []
    if is_linux():
        for dev in glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*") + \
                glob.glob("/dev/rfcomm*") + glob.glob("/dev/serial/by-id/*"):
            candidates.append(dev)
    else:
        import subprocess
        out = subprocess.run(["powershell", "-Command",
                              "Get-WmiObject Win32_SerialPort | "
                              "Select-Object -ExpandProperty DeviceID"],
                             capture_output=True, text=True, timeout=20).stdout
        candidates = [l.strip() for l in out.splitlines() if l.strip()]
    return candidates


def _open(port: str, baud: int = 115200, timeout: float = 2):
    serial = _serial()
    if serial is None:
        raise RuntimeError("pyserial not installed (pip install pyserial)")
    return serial.Serial(port, baud, timeout=timeout, write_timeout=2)


def at_command(port: str, cmd: str, baud: int = 115200, timeout: float = 5) -> str:
    """Send one AT command and return the full response text."""
    try:
        ser = _open(port, baud, timeout)
        ser.write((cmd + "\r\n").encode())
        time.sleep(0.4)
        resp = ser.read(4096).decode(errors="replace")
        ser.close()
        return resp.strip()
    except Exception as e:
        return f"ERROR: {e}"


def at_interactive(port: str, baud: int = 115200):
    """Raw interactive AT console."""
    ui.section("AT Console", f"{port} @ {baud}")
    ui.info("Type AT commands. 'quit' exits. Try ATI, AT+CGMI, AT+CGMM ...")
    ser = _open(port, baud)
    try:
        while True:
            cmd = ui.ask("AT>").strip()
            if not cmd:
                continue
            if cmd.lower() in ("quit", "exit", "q"):
                break
            ser.write((cmd + "\r\n").encode())
            time.sleep(0.5)
            resp = ser.read(4096).decode(errors="replace")
            print(resp.strip())
    finally:
        try:
            ser.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# SIM identity
# --------------------------------------------------------------------------

def sim_identity(port: str) -> dict:
    """Read ICCID, IMSI, MSISDN, operator, SPN from the SIM."""
    info = {"port": port}
    pairs = [
        ("ICCID", "AT+CCID"),
        ("IMSI", "AT+CIMI"),
        ("MSISDN", "AT+CNUM"),
        ("Operator", "AT+COPS?"),
        ("Manufacturer", "AT+CGMI"),
        ("Model", "AT+CGMM"),
        ("Revision", "AT+CGMR"),
        ("IMEI", "AT+CGSN"),
        ("SIM status", "AT+CPIN?"),
        ("Signal (CSQ)", "AT+CSQ"),
    ]
    for label, cmd in pairs:
        r = at_command(port, cmd)
        info[label] = r
    return info


def sim_info_menu(port: str) -> None:
    info = sim_identity(port)
    ui.show_table("SIM / Modem Identity", ["Field", "Response"],
                  [[k, v] for k, v in info.items()])
    CONFIG.save("cellular_identity", info)


# --------------------------------------------------------------------------
# Network registration + cell tower
# --------------------------------------------------------------------------

def network_registration(port: str) -> dict:
    """RAT, operator and current LAC/CID."""
    reg = at_command(port, "AT+CREG?")
    cgreg = at_command(port, "AT+CGREG?")
    cops = at_command(port, "AT+COPS?")
    csq = at_command(port, "AT+CSQ")
    return {"CREG": reg, "CGREG": cgreg, "COPS": cops, "CSQ": csq}


def cell_scan(port: str) -> list:
    """Enumerate neighbour cell towers if the modem supports it."""
    towers = []
    # Modern modems: AT+CNETSCAN or AT+CELLINFO / AT+CCED
    for cmd in ("AT+CNETSCAN", "AT+CELLINFO=1", "AT+CCED=0,7"):
        r = at_command(port, cmd, timeout=8)
        for line in r.splitlines():
            line = line.strip()
            if line.startswith(("+CNETSCAN", "+CELLINFO", "+CCED", "OK", "ERROR")):
                if line.startswith(("+CNETSCAN", "+CELLINFO", "+CCED")):
                    towers.append(line)
        if towers:
            break
    if not towers:
        # Fallback: LAC/CID + neighbours via AT+CREG and AT+CLS
        towers = network_registration(port)
    return towers


def monitor_cells(port: str, interval: float = 3.0):
    """Live cell tower monitor - watch for sudden changes (IMSI catcher)."""
    ui.section("Cell Tower Monitor", "watch LAC/CID changes (IMSI-catcher detection)")
    prev = {}
    try:
        while True:
            reg = at_command(port, "AT+CREG?")
            cid = re.search(r"CREG:.*,\s*(\d+),(\d+)", reg)
            csq = at_command(port, "AT+CSQ")
            m = re.search(r"CSQ:\s*(\d+),", csq)
            sig = m.group(1) if m else "?"
            cur = reg.strip()
            if cur not in prev:
                if prev:
                    ui.warn(f"[CELL-CHANGE] {prev} -> {cur}")
                else:
                    ui.info(f"Registered: {cur}  signal={sig}")
                prev[cur] = time.time()
            else:
                ui.info(f"Stable: {cur}  signal={sig}")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    ui.info("Monitoring stopped.")


# --------------------------------------------------------------------------
# SMS
# --------------------------------------------------------------------------

def sms_read(port: str, mode: str = "AT+CMGL=\"ALL\"") -> list:
    """Read SMS messages from the SIM card."""
    ui.section("SMS Inbox", f"{port}")
    resp = at_command(port, 'AT+CMGF=1')
    resp = at_command(port, mode)
    messages = []
    for line in resp.splitlines():
        m = re.match(r"\+CMGL:\s*(\d+),(.*)", line)
        if m:
            idx = m.group(1)
            rest = line.split("\"")[0]
            messages.append({"index": idx, "raw": line, "context": ""})
    # reconstruct: lines after +CMGL are the text
    lines = resp.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("+CMGL:"):
            if i + 1 < len(lines) and not lines[i + 1].startswith("+"):
                messages[-1]["context"] = lines[i + 1]
    if not messages:
        ui.info("No SMS messages or modem reports empty.")
    return messages


def sms_send(port: str, number: str, text: str) -> bool:
    """Send an SMS via AT+CMGS."""
    ui.info(f"Sending SMS to {number} ...")
    ser = _open(port, 115200)
    try:
        ser.write(b'AT+CMGF=1\r\n')
        time.sleep(0.3)
        ser.read(1024)
        ser.write(b'AT+CMGS="' + number.encode() + b'"\r\n')
        time.sleep(0.3)
        ser.read(1024)
        ser.write(text.encode() + b"\x1a")
        time.sleep(1)
        resp = ser.read(2048).decode(errors="replace")
        ser.close()
        if "+CMGS" in resp:
            ui.ok(f"SMS sent. {resp.strip()[:80]}")
            return True
        ui.warn(f"SMS result: {resp.strip()[:120]}")
        return False
    except Exception as e:
        ui.error(str(e))
        return False


def sms_wipe(port: str) -> None:
    """Delete all SMS from the SIM."""
    ui.warn("Wiping SIM SMS... authorized testing only.")
    msgs = sms_read(port)
    for m in msgs:
        at_command(port, f'AT+CMGD={m["index"]},0')
    ui.ok("SMS wiped.")


# --------------------------------------------------------------------------
# USSD
# --------------------------------------------------------------------------

def ussd_send(port: str, code: str):
    """Send a USSD code and return the response."""
    ui.section("USSD", f"{code}")
    resp = at_command(port, f'AT+CUSD=1,"{code}",15', timeout=10)
    ui.info(resp or "No response.")
    return resp


# --------------------------------------------------------------------------
# External hardware bridges (SDR / osmocom)
# --------------------------------------------------------------------------

def sdr_tools() -> list:
    """Detect SDR / cellular tooling on the box."""
    return {t: which(t) for t in
            ["grgsm_livemon", "grgsm_scanner", "kal", "kalibrate-rtl",
             "osmocom_fft", "rtl_test", "gqrx", "gammu", "AT+"]}


def grgsm_scan(seconds: int = 30):
    """Scan GSM downlink spectrum (requires gr-gsm + RTL-SDR)."""
    if not which("grgsm_scanner"):
        ui.warn("grgsm_scanner not found. Install gr-gsm + RTL-SDR drivers.")
        return
    ui.section("GSM Spectrum Scan", "grgsm_scanner")
    ui.info("Scanning 900/1800 MHz downlink...")
    from open80211.core.interfaces import system_command
    rc, out = system_command("grgsm_scanner", timeout=seconds + 30)
    ui.info(out[-2000:])
    if rc != 0:
        ui.warn("Scanner exited non-zero. Check RTL-SDR + permissions.")


def gammu_bridge(command: str = "identify"):
    """Bridge to gammu for deep SIM ops (install: apt install gammu)."""
    if not which("gammu"):
        ui.warn("gammu not found. Install: apt install gammu")
        return
    from open80211.core.interfaces import system_command
    rc, out = system_command(f"gammu {command}", timeout=60)
    ui.info(out[-2000:])


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def cell_menu(iface: str = "") -> None:
    ports = find_modems()
    if not ports:
        ui.warn("No serial modems found. Connect a USB GSM/LTE stick "
                "(Huawei/Quectel) or a rooted phone in modem mode.")
        ui.info("Tip: on Android enable 'USB tethering' or use the "
                "'Serial USB Terminal' app via ADB forward.")
        adb = which("adb")
        if adb:
            ui.info("ADB detected. Use: adb shell am start "
                    "-a android.intent.action.RUN ... to bridge AT over TCP.")
        return
    if len(ports) == 1:
        port = ports[0]
        ui.ok(f"Using modem: {port}")
    else:
        idx = ui.menu("Select modem", ports)
        if not idx:
            return
        port = ports[idx - 1]

    while True:
        choice = ui.menu("Cellular / SIM Suite", [
            "SIM / modem identity (ICCID, IMSI, IMEI)",
            "Network registration + current cell (LAC/CID)",
            "Scan neighbour cell towers",
            "Monitor cells (IMSI-catcher detection)",
            "SMS - read inbox",
            "SMS - send message",
            "SMS - wipe SIM",
            "USSD codes",
            "Raw AT command console",
            "GSM spectrum scan (gr-gsm + RTL-SDR)",
            "gammu bridge",
            "Detect SDR hardware",
        ])
        if choice == 0:
            return
        if choice == 1:
            sim_info_menu(port)
        elif choice == 2:
            reg = network_registration(port)
            ui.show_table("Network Registration", ["Query", "Response"],
                          [[k, v] for k, v in reg.items()])
        elif choice == 3:
            towers = cell_scan(port)
            if isinstance(towers, list):
                for t in towers:
                    ui.info(t)
            else:
                ui.show_table("Neighbour Cells", ["Query", "Response"],
                              [[k, v] for k, v in towers.items()])
        elif choice == 4:
            monitor_cells(port)
        elif choice == 5:
            msgs = sms_read(port)
            if msgs:
                ui.show_table("SMS", ["Index", "Text"],
                              [[m["index"], m["context"]] for m in msgs])
        elif choice == 6:
            number = ui.ask("Recipient number")
            text = ui.ask("Message body")
            if number and text:
                sms_send(port, number, text)
        elif choice == 7:
            ui.warn("This deletes SMS from the SIM card. Authorized use only.")
            if ui.confirm("Continue?", default=False):
                sms_wipe(port)
        elif choice == 8:
            code = ui.ask("USSD code (e.g. *#06#, *100#)")
            ussd_send(port, code)
        elif choice == 9:
            at_interactive(port)
        elif choice == 10:
            secs = ui.ask_int("Scan seconds", default=30)
            grgsm_scan(secs)
        elif choice == 11:
            cmd = ui.ask("gammu command", default="identify")
            gammu_bridge(cmd)
        elif choice == 12:
            ui.show_table("SDR Tools", ["Tool", "Status"],
                          [[t, "OK" if v else "missing"] for t, v in sdr_tools().items()])