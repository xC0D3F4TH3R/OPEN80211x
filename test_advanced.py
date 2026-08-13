"""Tests for the advanced suite additions: WEP, NTLMv2 responder, TLS CA, exports, report."""
import io
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from open80211.modules import wep, lan, report, mitm
from open80211.core import netutils as nu, crypto, integrations

print("== 1. WEP RC4 + ICV ==")
import zlib
plain = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
iv = b"\x01\x02\x03"
key = bytes.fromhex("0102030405")
crc = wep.struct_crc32(plain)
keystream = wep._rc4(iv + key, plain + crc)
ciphertext = plain + crc  # in WEP the ciphertext includes ICV encrypted
ct = bytes(a ^ b for a, b in zip(plain + crc, wep._rc4(iv + key, b"\x00" * len(plain + crc))))
dec, ok = wep.wep_decrypt(iv, key, ct)
assert ok and dec == plain, (ok, dec)
print("  WEP decrypt + ICV check OK:", dec[:20])

print("== 2. ResponderLite NTLMv2 parse ==")
def build_ntlmv2_auth(user, domain, nt_resp):
    user_b = user.encode("utf-16le"); dom_b = domain.encode("utf-16le")
    lm = b"\x00" * 24
    b = b"NTLMSSP\x00" + struct.pack("<I", 3)
    payload_off = 8 + 4 + 8 * 6 + 4  # signature+type+6 SecBufs+flags = 64
    def secbuf(payload, start):
        return struct.pack("<H", len(payload)) + struct.pack("<H", len(payload)) + \
               struct.pack("<I", start)
    off = payload_off
    lm_off = off; off += len(lm)
    nt_off = off; off += len(nt_resp)
    dom_off = off; off += len(dom_b)
    user_off = off; off += len(user_b)
    wks_off = off; off += len(b"WKST")
    b += secbuf(lm, lm_off) + secbuf(nt_resp, nt_off) + secbuf(dom_b, dom_off) + \
         secbuf(user_b, user_off) + secbuf(b"WKST", wks_off) + secbuf(b"", 0)
    b += struct.pack("<I", 0x00000000)
    b += lm + nt_resp + dom_b + user_b + b"WKST"
    return b

proof = bytes(range(16))
blob = b"\x01\x01\x00\x00" + b"\x00"*4 + b"\x01"*8 + b"\x02"*8 + b"\x03"*4 + b"\x00"*4
ntv2 = proof + blob
auth = build_ntlmv2_auth("alice", "ACME", ntv2)

r = lan.ResponderLite("eth0", "10.0.0.2")
r._parse_auth(auth, "192.168.1.50", bytes(range(8)))
print("  captured:", r.captured)
assert r.captured and r.captured[0]["user"] == "alice"
assert r.captured[0]["domain"] == "ACME"
assert r.captured[0]["ntlmv2"]["proof"] == proof.hex()
assert r.captured[0]["ntlmv2"]["blob"].startswith("01010000")
print("  NTLMv2 parse OK")

print("== 3. TLS MITM CA + cert mint ==")
ca = mitm.MITMCA()
cert, key = ca.leaf("bank.example.com")
assert b"CERTIFICATE" in cert and b"PRIVATE KEY" in key
from cryptography import x509
parsed = x509.load_pem_x509_certificate(cert)
sans = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert "bank.example.com" in sans.get_values_for_type(x509.DNSName)
print("  CA + leaf cert OK, SAN:", sans.get_values_for_type(x509.DNSName))

print("== 4. hashcat 22000 export ==")
import open80211.core.config as cfg
p = integrations.export_hc22000(hs_dict := {
    "ap_mac": "aa:bb:cc:dd:ee:ff", "sta_mac": "11:22:33:44:55:66",
    "anonce": "00"*32, "snonce": "11"*32, "pmkid": "aa"*16,
    "eapol_msgs": [{"key_info": "0x8ca", "mic": "bb"*16}]}, "TestNet")
line = open(p).read()
assert line.startswith("WPA*01*bb" * 0 or "WPA*01*") and "*TestNet" in line
print("  22000 OK:", line.strip()[:60])

print("== 5. WPA3/SAE detection ==")
from scapy.all import Dot11, Dot11Beacon, Dot11Elt
# RSN element built field-by-field: version, group, pair_count+pairs,
# akm_count+akm (SAE 000fac08), capabilities
rsn = (bytes([0x00, 0x01]) + bytes.fromhex("000fac04") +
       bytes([0x00, 0x01]) + bytes.fromhex("000fac04") +
       bytes([0x00, 0x01]) + bytes.fromhex("000fac08") +
       bytes([0x00, 0x0c]))
beacon = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
               addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
    Dot11Beacon(cap=0x2111) / Dot11Elt(ID=0, info=b"WPA3Net") / \
    Dot11Elt(ID=48, info=rsn)
enc = nu.encryption_info(beacon)
print("  WPA3 beacon enc:", enc)
assert "WPA3" in enc and "SAE" in enc

print("== 6. HTML report ==")
path = report.build_report(
    scan=[{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Test", "channel": 6,
           "enc": "WPA2-CCMP (PSK)", "signal": -55, "clients_detected": []}],
    creds=[{"protocol": "HTTP", "data": "user=admin&pass=hunter2", "src": "10.0.0.5"}],
    cracked=[("Test", "hunter2")])
html = open(path, encoding="utf-8").read()
assert "open80211 Wireless Security Assessment" in html and "hunter2" in html
assert "WPA2-PSK" in html and "Plaintext credentials observed" in html
print("  Report OK,", len(html), "bytes")

print("\nALL ADVANCED TESTS PASSED")