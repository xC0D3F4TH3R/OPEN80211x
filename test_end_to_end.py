"""
End-to-end self-test: builds a synthetic WPA2 capture (4-way handshake +
CCMP-encrypted data frame) using pycryptodome, then validates that
open80211 can extract the handshake, crack the PSK, and decrypt the data.

Run from the repo root:  python test_end_to_end.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from open80211.core import crypto
from Crypto.Cipher import AES as A

SSID = "testssid"
PASS = "password123"
AP = "aa:bb:cc:dd:ee:ff"
STA = "11:22:33:44:55:66"
ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))

pmk = crypto.pbkdf2_psk(PASS, SSID)
ptk = crypto.derive_ptk(pmk, AP, STA, ANONCE, SNONCE)
kck, tk = ptk[:16], ptk[32:48]

def eapol_key(key_info, nonce, mic=b"\x00"*16, key_data=b"", replay=b"\x00"*8):
    body = struct.pack(">H", key_info) + struct.pack(">H", 0) + replay + nonce
    body += b"\x00"*16 + b"\x00"*8 + b"\x00"*8 + mic + struct.pack(">H", len(key_data)) + key_data
    hdr = bytes([2, 3]) + struct.pack(">H", len(body))
    return hdr + body

def wrap(dot11_bytes, src, dst):
    from scapy.all import RadioTap, Dot11
    return RadioTap() / Dot11(bytes(dot11_bytes))

def make_msg(n, src, dst):
    if n == 1:
        ki = 0x0002 | 0x0008 | 0x0010 | 0x0020   # ver2, pairwise, install, ack
        pmkid_val = crypto.pmkid(pmk, AP, STA)
        kde = bytes([221, 20]) + b"\x00\x0f\xac\x04" + pmkid_val
        eapol = eapol_key(ki, ANONCE, key_data=kde)
    elif n == 2:
        ki = 0x0002 | 0x0008 | 0x0040             # ver2, pairwise, mic
        eapol = eapol_key(ki, SNONCE)
        eapol = eapol[:80] + crypto.compute_eapol_mic(kck, eapol) + eapol[96:]
    elif n == 3:
        ki = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080
        eapol = eapol_key(ki, ANONCE)
        eapol = eapol[:80] + crypto.compute_eapol_mic(kck, eapol) + eapol[96:]
    else:
        ki = 0x0002 | 0x0008 | 0x0040 | 0x0080
        eapol = eapol_key(ki, SNONCE)
        eapol = eapol[:80] + crypto.compute_eapol_mic(kck, eapol) + eapol[96:]
    llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    payload = llc + eapol
    src_b = bytes.fromhex(src.replace(":", ""))
    dst_b = bytes.fromhex(dst.replace(":", ""))
    header = bytes([0x08, 0x01]) + b"\x00\x00" + dst_b + src_b + src_b \
        + struct.pack(">H", 0x0001)
    return wrap(header + payload, src, dst)

def make_data(pn, ip_payload):
    # FromDS data frame, non-QoS: FC = 0x0108
    header = bytes([0x08, 0x01]) + b"\x00\x00" \
        + bytes.fromhex(STA.replace(":", "")) \
        + bytes.fromhex(AP.replace(":", "")) \
        + bytes.fromhex(AP.replace(":", "")) \
        + struct.pack(">H", 0x0101)
    aad, _, _ = crypto.ccmp_aad(header + b"\x00"*8)
    pn_be = pn.to_bytes(6, "big")
    a2 = bytes.fromhex(AP.replace(":", ""))
    nonce = b"\x00" + a2 + pn_be
    enc = A.new(tk, A.MODE_CCM, nonce=nonce, mac_len=8)
    enc.update(aad)
    ct = enc.encrypt(ip_payload) + enc.digest()
    ccmp_hdr = bytes([0x20]) + pn.to_bytes(6, "little") + b"\x00"
    return wrap(header + ccmp_hdr + ct, STA, AP)

# ---- build pcap ----
from scapy.all import wrpcap
frames = [
    make_msg(1, AP, STA),
    make_msg(2, STA, AP),
    make_msg(3, AP, STA),
    make_msg(4, STA, AP),
    make_data(0x102030405, b"\x45\x00\x00\x28" + b"\x00"*20 + b"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"),
    make_data(0x102030406, b"\x45\x00\x00\x20" + b"\x00"*16 + b"POST /login user=admin pass=hunter2"),
]
pcap = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "results", "test_handshake.pcap")
wrpcap(pcap, frames)

# ---- 1) extract handshake ----
hs = crypto.extract_handshake(pcap)
print("ap_mac:", hs["ap_mac"], "sta:", hs["sta_mac"])
print("anonce:", hs["anonce"][:12], "snonce:", hs["snonce"][:12])
print("pmkid:", hs["pmkid"], "eapol_msgs:", hs["count"])
assert hs["ap_mac"] == AP and hs["sta_mac"] == STA
assert hs["anonce"] and hs["snonce"] and hs["pmkid"] == crypto.pmkid(pmk, AP, STA).hex()

# ---- 2) crack ----
found = crypto.crack_psk(["wrongpass", "password", PASS, "admin"], SSID, hs)
print("crack result:", found)
assert found == PASS

# ---- 3) decrypt data frames ----
res = crypto.decrypt_wpa_capture(pcap, PASS, SSID)
print("decrypted frames:", len(res["decrypted"]))
for item in res["decrypted"]:
    print("   ", item["src"], "->", item["dst"], item["data"][:60])
assert len(res["decrypted"]) == 2
assert b"GET /admin" in bytes.fromhex(res["decrypted"][0]["data"])

print("\nEND-TO-END TEST PASSED")