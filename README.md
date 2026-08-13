# open80211 — Advanced Wireless Penetration Testing Suite

A complete, user-friendly CLI suite for wireless AND network penetration
testing: recon, capture, attacks, MITM, rogue AP, LAN post-exploitation,
cracking, decryption, and professional reporting. **Ethical use only** — test
only networks you own or have written permission to assess.

```
   ___                 ______ ____  ____ _  ___   ____
  / _ \___  ____  __  / __/ // / _ )/ __ ) |/ ( ) / / /__
 / // / _ \/ __/ |/_/ _\ \/ _  / _  | / _ /    /| / / _ \
/____/\___/\__/  _>_</___/_/ /_/ ____/_/ \_/___ |_/_//_/
                          |___/  WIRELESS PENTEST SUITE
```

## Capability matrix

| Suite | What it does |
|-------|--------------|
| **Setup** | Interface picker, monitor mode, channel control, MAC spoofing, dependency/arsenal detector |
| **Recon** | AP discovery (2.4/5 GHz), SSID/BSSID/channel/encryption/signal/clients, **WPA3/SAE/OWE detection**, client probing, wardriving (CSV), auto-reports |
| **Capture** | Live tcpdump-style decode of every packet, protocol/port filters, live stats, pcap export, hex dumps, protocol breakdown |
| **Attacks** | Deauth flood (targeted/broadcast/continuous), beacon flood, association flood, probe flood, WPS (reaver), **injection tester**, arbitrary frame injector |
| **MITM** | ARP spoof, DNS spoof, SSL strip (HTTP downgrade), **HTTPS interception (dynamic CA + per-host certs)**, session tracking, credential/cookie harvesting, TLS-SNI fingerprinting, live real-time feed |
| **Evil AP** | Rogue AP (open/WPA2), **WPA-EAP enterprise evil twin** (MSCHAPv2 capture), **Karma/MANA** responder, captive portal credential logging, beacon impersonation |
| **LAN** | ARP host discovery, SYN/connect port scan + banner grab, **DHCP starvation**, **rogue DHCP**, **LLMNR/NBT-NS/mDNS poisoning + NTLMv2 hash capture** (Responder-style, hashcat 5600 export), ICMP redirect |
| **WEP** | Fake authentication, ARP replay + IV collection, PRGA keystream capture, pure-Python RC4 decrypt, aircrack-ng bridge |
| **Analysis** | Handshake + **PMKID** capture, pure-Python WPA2-PSK cracker (PMKID + EAPOL-MIC), **WPA2 traffic decryption (AES-CCMP)**, pcap inspection, **hash exports** |
| **Reports** | Self-contained **HTML assessment report** with findings, severity, and remediation |

All results (pcaps, logs, captured credentials, cracked keys, hashes, reports)
are saved under `results/session-<timestamp>/`.

## Industry interop

open80211 speaks the ecosystem's formats so you can hand off to your usual
arsenal:

```
hashcat -m 22000 results/.../crack-<ssid>.hc22000 wordlist.txt   # WPA2 PSK
hashcat -m 5600  results/.../hashes-ntlmv2.txt  wordlist.txt      # NTLMv2
aircrack-ng -b BSSID -w wordlist capture.pcap
aircrack-ng capture-wep-ivs.pcap                                   # WEP
```

Exports built in: **hashcat 22000**, **cowpatty**, **hccapx** (via wpaclean),
**NTLMv2 5600**. Optional bridges: aircrack-ng, aireplay-ng, reaver,
hostapd(-mana), dnsmasq, bettercap, responder, tcpdump, hcxdumptool.

## Installation

Requires Python 3.9+. Full wireless features require **Linux** with a card
supporting monitor mode + injection (e.g. Kali + Alfa). Capture/analysis and
the LAN suite work anywhere scapy can sniff.

```bash
cd open80211
pip install -r requirements.txt

# Kali/Debian extras for the full arsenal:
sudo apt install hostapd hostapd-mana dnsmasq aircrack-ng reaver tcpdump iw hashcat
```

## Quick start

```bash
python open80211.py                    # interactive menu
python open80211.py --scan -i wlan0    # one-shot AP scan
python open80211.py --scan --monitor   # auto monitor-mode scan
```

## Typical engagements

**Wireless takeover (WPA2-PSK)**
1. Setup → monitor mode → Recon → find target AP.
2. Analysis → *Capture PMKID/handshake* (auto-deauth) → *Crack* or export 22000.
3. Decrypt any saved capture with the recovered passphrase.

**Man-in-the-middle**
1. MITM → *Full console* → ARP spoof victim → watch live feed.
2. DNS-spoof specific domains; SSL-strip HTTP; HTTPS-intercept (install
   `results/.../mitm-ca/ca.crt` as trusted CA on the target).

**Credential harvesting**
1. LAN → *LLMNR/NBT-NS/mDNS poisoning* → trigger victim auth → NTLMv2 in `hashes-ntlmv2.txt`.
2. Evil AP → *Enterprise evil twin* or captive portal → harvest MSCHAPv2/portal creds.

**Reporting**
1. Run your engagement, then Main → *Report Generator* → open the HTML report.

## Architecture

```
open80211/
├── open80211.py            entry point (menu + quick commands)
├── open80211/
│   ├── menu.py             interactive menus
│   ├── core/
│   │   ├── config.py       settings, results storage, privileges
│   │   ├── ui.py           rich UI (banners, tables, prompts, live views)
│   │   ├── interfaces.py   cards, monitor mode, channels, MAC spoof
│   │   ├── netutils.py     MAC/IP math + full protocol decoder (WPA3/SAE too)
│   │   ├── crypto.py       WPA key derivation, CCMP decrypt, PSK cracking
│   │   └── integrations.py hash exports (22000/5600/hccapx/cowpatty)
│   └── modules/
│       ├── recon.py        AP/client discovery, wardriving
│       ├── capture.py      live tcpdump-style capture
│       ├── attacks.py      deauth/flood/WPS/injection/frame injector
│       ├── mitm.py         ARP+DNS+SSLstrip+HTTPS intercept engine
│       ├── evilap.py       rogue/enterprise/karma AP + captive portal
│       ├── lan.py          LAN suite (scan, DHCP, poisoning, NTLMv2)
│       ├── wep.py          legacy WEP attack suite
│       ├── analysis.py     handshake/PMKID, crack, decrypt, inspect
│       └── report.py       HTML assessment report
├── test_end_to_end.py      self-test (handshake→crack→decrypt)
├── test_advanced.py        self-test (WEP, NTLMv2, TLS CA, exports, WPA3)
└── requirements.txt
```

## Security notes / honest limitations

- **PMF (802.11w)** blocks spoofed deauth; WPA3-SAE needs an SAE-capable
  adapter and is noted in recon rather than fully attacked.
- **TKIP** is not re-decrypted (deprecated cipher) — TKIP networks are still
  crackable via handshake.
- **HTTPS interception** requires the target to trust our generated CA
  (`results/.../mitm-ca/ca.crt`); cert-pinned apps will refuse.
- Live-injection features need monitor-mode drivers; behavior varies by card.

## Legal disclaimer

This software is for **authorized security testing and research only**. The
developer assumes no liability for misuse. Unauthorized interception or access
of wireless/wired networks may violate local, national, and international law.
You are responsible for complying with all applicable regulations.