<div align="center">

```
  ___                 ______ ____  ____ _  ___   ____
 / _ \___  ____  __  / __/ // / _ )/ __ ) |/ ( ) / / /__
// / _ \/ __/ __/ |/_/ _\ \/ _  / _  | / _ /    /| / / _ \
/____/\___/__/  _>_</___/_/ /_/ ____/_/ \_/___ |_/_//_/
                          |___/  WIRELESS PENTEST SUITE
```

# ⚡ OPEN80211x v2.1

### *The Professional Wireless & Network Penetration Testing Suite*

*One CLI, two operation modes — from 802.11 air attacks to Bluetooth, cellular, IoT, and post-exploitation. Anchored by an engagement console with a shared target registry.*

[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge&logo=openbadges)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20Kali-1793D1?style=for-the-badge&logo=linux)](README.md)

> 🛡️ **ETHICAL USE ONLY** — test only networks & systems you own or are authorized to assess.
> Unauthorized use may violate local, national, and international law.

</div>

---

## 🚀 Two Operation Modes

The suite is organized the way a professional engagement is run — one shared target registry, killchain wizards, and two op modes:

```
┌───────────────────────────────────────────────────────────────┐
│  ⚡ OPEN80211 v2.1 — Professional Wireless Pentest Suite        │
│  01 ENGAGEMENT CONSOLE   → killchains · target registry ·      │
│                             timeline · notes · live dashboard  │
│  02 ATTACK WITHOUT MONITOR MODE → works on any connected NIC    │
│  03 ATTACK WITH MONITOR MODE    → needs a monitor-capable card  │
│  04 Workspaces (named engagements) · Report · Setup · Help      │
└───────────────────────────────────────────────────────────────┘
```

### 🎯 Engagement Console (recommended start)

Every module writes findings into a **shared target registry**, so nothing is ever re-typed and the report covers the whole engagement:

- **Killchain wizards** — guided chains for WPA2 / LAN / IoT / Bluetooth that run recon → attack → crack → report automatically.
- **Target registry** — APs, hosts, Bluetooth & IoT devices, credentials; any attack menu can *pick* a target from the registry instead of re-entering BSSID/MAC/IP.
- **Engagement timeline** — every action is timestamped; turn it into report section 13.
- **Notes** — per-engagement field notes that land in report section 14.
- **Workspaces** — named per-client folders under `results/workspaces/<name>/`; create, switch, and resume anytime (targets, captures, notes all persist).

### ⚔️ ATTACK WITHOUT MONITOR MODE

| Suite | Capabilities |
|-------|--------------|
| **Spoofing / Identity** | MAC changer with **vendor OUI database** (Apple/Samsung/Intel…), random vendor MACs, MAC restore, IP spoofing (raw packets), **802.11 MAC spoofing**, standalone ARP spoofing |
| **MITM** | ARP + DNS spoof · SSL-strip · **HTTPS interception** (dynamic CA) · credential/cookie harvest · TLS-SNI fingerprint · live feed |
| **LAN / Network** | ARP discovery · port scan + banner · DHCP starvation / rogue DHCP · **LLMNR/NBT-NS/mDNS → NTLMv2** · ICMP redirect |
| **Brute Force** | SSH / FTP / HTTP-Basic / Telnet / **SMB** online attacks · threaded engine · hydra bridge · starter wordlist generator |
| **Bluetooth** | Classic + BLE scan · device fingerprint (SDP/RSSI) · RFCOMM · legacy PIN attack · PIN brute force · **KNOB check** · L2CAP flood · BT MAC spoof · BLE beacon spam |
| **Cellular / SIM** | Modem discovery · AT console · **ICCID/IMSI/IMEI** · cell tower scan (LAC/CID) · **IMSI-catcher monitor** · SMS read/send/wipe · USSD · GSM spectrum scan (gr-gsm) |
| **IoT** | MQTT fingerprint / **topic enumeration / injection** · UPnP/SSDP · RTSP camera probe · CoAP · Modbus/TCP · default-credential check · subnet discovery sweep |
| **Packet Sniffing** | Managed-mode live capture · filters · stats · pcap export |

### 📡 ATTACK WITH MONITOR MODE

| Suite | Capabilities |
|-------|--------------|
| **Recon** | AP discovery 2.4/5 GHz · **WPA3/SAE/OWE detection** · client probing · wardriving CSV · full guided recon |
| **Attack Suite** | Deauth flood · beacon/assoc/probe flood · WPS (reaver) · injection test · raw frame injector |
| **Evil AP** | Rogue AP (open/WPA2) · **WPA-EAP enterprise evil twin** · **Karma/MANA** · **PMKID-capture twin** · **WPA3/SAE Dragonblood downgrade check** · 4 captive-portal templates |
| **WEP** | Fake auth · ARP replay · PRGA capture · pure-Python RC4 decrypt · aircrack bridge |
| **Analysis** | Handshake + **PMKID** capture · pure-Python **WPA2-PSK cracker** · **AES-CCMP traffic decryption** · pcap inspection · hash exports |

---

## 🧰 What's Under the Hood

- **Pure-Python crypto** — PBKDF2 → PMK → PTK, PMKID, EAPOL MIC, AES-CCMP decryption, RC4/WEP, NTLMv2 parsing. No external cracking deps required.
- **180+ OUI vendor database** — believable MAC impersonation for every spoofing scenario.
- **Self-contained responders** — LLMNR/NBT-NS/mDNS poisoning + SMB NTLMv2 capture written from scratch (no Responder dependency).
- **Dynamic MITM CA** — on-the-fly per-host TLS certs for HTTPS interception.
- **External bridges auto-detected** — aircrack-ng, hashcat, hostapd(-mana), reaver, hydra, gr-gsm, gammu, bluetoothctl, hcitool and more.

## 📁 Output & Artifacts

All results live under `results/` — either `session-<timestamp>/` or a named workspace under `results/workspaces/<name>/`:

| Artifact | Description |
|----------|-------------|
| `targets.json` | shared engagement registry (APs, hosts, BT, IoT, creds) |
| `timeline.json` / `notes.json` | engagement timeline + field notes |
| `capture.pcap` / `handshake-*.pcap` | raw traffic captures |
| `crack-<ssid>.hc22000` | hashcat 22000 WPA2 hash |
| `hashes-ntlmv2.txt` | hashcat 5600 NTLMv2 hashes |
| `mitm-ca/ca.crt` | generated CA for HTTPS interception |
| `twin-<ssid>.handshakes` | PMKID/handshake captures from evil twin |
| `portal_credentials.log` | captive portal submissions |
| `brute-*.json` / `iot_discovery.json` / `cellular_identity.json` | structured findings |
| `open80211-report.html` | full HTML assessment report (15 sections incl. timeline + notes) |

> 🔒 `.gitignore` automatically excludes pcaps, hashes, keys, certs, and all `results/` artifacts.

---

## ⚡ Quick Start

```bash
pip install -r requirements.txt
python open80211.py                       # interactive menu (two modes)
python open80211.py --scan -i wlan0       # one-shot AP scan
python open80211.py --scan --monitor -c 6 # auto monitor-mode scan
```

Optional suite extras:

```bash
pip install "open80211[all]"              # pyserial, paho-mqtt, bleak, paramiko, impacket
apt install hostapd hostapd-mana dnsmasq aircrack-ng reaver tcpdump iw bluez
```

## 🧪 Testing

```bash
python -m compileall -q .   # syntax check
python test_end_to_end.py   # handshake → crack → CCMP decrypt
python test_advanced.py     # WEP · NTLMv2 · TLS CA · exports · report
```

---

## ⚖️ Legal Disclaimer

> This software is provided for **authorized security testing and research only**. Unauthorized interception, disruption, or access of wireless or wired networks, Bluetooth devices, cellular networks, or IoT devices may violate local, national, and international law. **You are solely responsible** for ensuring your activities are permitted and for any consequences of misuse. The author(s) assume no liability whatsoever.

<div align="center">

**Made with 💀 by security researchers — use your powers for good.**

</div>
