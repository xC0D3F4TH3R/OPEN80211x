"""
Cryptographic engine for WPA/WPA2-PSK analysis.

Implements, in pure Python (with optional pycryptodome acceleration):
  * PBKDF2-SHA1 PSK -> PMK
  * PRF-512 pairwise key expansion (KCK/KEK/TK/MIC keys)
  * PMKID computation
  * EAPOL-Key MIC verification (for 4-way handshake cracking)
  * AES-CCMP decryption of WPA2 encrypted data frames
  * Full pcap WPA2 decrypt + handshake extraction

TKIP decryption is intentionally not re-implemented (deprecated cipher);
TKIP networks can still be handshake-cracked and attacked via other modules.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# --------------------------------------------------------------------------
# AES (128-bit) - pycryptodome preferred, pure-Python fallback included
# --------------------------------------------------------------------------

try:
    from Crypto.Cipher import AES as _PyAES

    def _aes_enc_block(key: bytes, block: bytes) -> bytes:
        return _PyAES.new(key, _PyAES.MODE_ECB).encrypt(block)

    AES_OK = True
except ImportError:
    AES_OK = False

    SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

    def _key_expansion(key: bytes):
        k = list(key)
        w = [k[i:i+4] for i in range(0, 16, 4)]
        for i in range(4, 44):
            t = w[i-1][:]
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= RCON[i // 4 - 1]
            w.append([w[i-4][j] ^ t[j] for j in range(4)])
        return w

    def _aes_enc_block(key: bytes, block: bytes) -> bytes:
        state = [list(block[i*4:i*4+4]) for i in range(4)]
        w = _key_expansion(key)
        def add_rk(rk):
            for c in range(4):
                for r in range(4):
                    state[r][c] ^= rk[c][r]
        def sub_bytes():
            for r in range(4):
                for c in range(4):
                    state[r][c] = SBOX[state[r][c]]
        def shift_rows():
            for r in range(1, 4):
                state[r] = state[r][r:] + state[r][:r]
        def mix_columns():
            for c in range(4):
                s0,s1,s2,s3 = state[0][c],state[1][c],state[2][c],state[3][c]
                state[0][c] = _gmul(s0,2) ^ _gmul(s1,3) ^ s2 ^ s3
                state[1][c] = s0 ^ _gmul(s1,2) ^ _gmul(s2,3) ^ s3
                state[2][c] = s0 ^ s1 ^ _gmul(s2,2) ^ _gmul(s3,3)
                state[3][c] = _gmul(s0,3) ^ s1 ^ s2 ^ _gmul(s3,2)
        add_rk(w[:4])
        for rnd in range(1, 10):
            sub_bytes(); shift_rows(); mix_columns(); add_rk(w[rnd*4:rnd*4+4])
        sub_bytes(); shift_rows(); add_rk(w[40:44])
        return bytes(state[r][c] for c in range(4) for r in range(4))

    def _gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------

def pbkdf2_psk(passphrase: str, ssid: str, iterations: int = 4096) -> bytes:
    """PSK (PMK) from passphrase + SSID via PBKDF2-SHA1."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"), iterations, 32)


def _prf_512(key: bytes, prefix: bytes, data: bytes) -> bytes:
    """PRF-512 per 802.11: HMAC-SHA1 over 4 counter iterations."""
    out = b""
    for i in range(1, 5):
        out += hmac.new(key, prefix + b"\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
    return out[:64]


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
               anonce: bytes, snonce: bytes) -> bytes:
    """PTK (64 bytes) for the pairwise key expansion."""
    aa = bytes.fromhex(ap_mac.replace(":", ""))
    sa = bytes.fromhex(sta_mac.replace(":", ""))
    if aa == sa:
        raise ValueError("AP and STA MAC are identical")
    if (aa, anonce) < (sa, snonce):
        a_min, a_max = aa, sa
        n_min, n_max = anonce, snonce
    else:
        a_min, a_max = sa, aa
        n_min, n_max = snonce, anonce
    return _prf_512(pmk, b"Pairwise key expansion", a_min + a_max + n_min + n_max)


def ptk_parts(ptk: bytes) -> dict:
    """Split PTK into named keys."""
    return {"kck": ptk[0:16], "kek": ptk[16:32],
            "tk": ptk[32:48], "mic_tx": ptk[48:56], "mic_rx": ptk[56:64]}


def pmkid(pmk: bytes, ap_mac: bytes, sta_mac: bytes) -> bytes:
    aa = bytes.fromhex(ap_mac.replace(":", ""))
    sa = bytes.fromhex(sta_mac.replace(":", ""))
    return hmac.new(pmk, b"PMK Name" + aa + sa, hashlib.sha1).digest()[:16]


# --------------------------------------------------------------------------
# EAPOL MIC (4-way handshake verification)
# --------------------------------------------------------------------------

MIC_OFFSET = 80  # EAPOL header(4) + keyinfo(2) + keylen(2) + replay(8) + nonce(32)
                # + iv(16) + rsc(8) + id(8) = 80; MIC field = bytes[80:96]


def compute_eapol_mic(kck: bytes, eapol: bytes) -> bytes:
    """MIC over the EAPOL-Key frame with the MIC field zeroed."""
    if len(eapol) < 96:
        return b""
    mic_data = eapol[:MIC_OFFSET] + b"\x00" * 16 + eapol[MIC_OFFSET + 16:]
    return hmac.new(kck, mic_data, hashlib.sha1).digest()[:16]


# --------------------------------------------------------------------------
# Handshake extraction from a capture
# --------------------------------------------------------------------------

def find_eapol_start(frame: bytes) -> int:
    """Offset of the EAPOL version byte inside an 802.11 data frame, or -1."""
    try:
        # LLC/SNAP header contains 0x888e ethertype
        idx = frame.find(b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
        if idx >= 0:
            return idx + 8
        idx = frame.find(b"\x88\x8e")
        return idx + 2 if idx >= 0 else -1
    except Exception:
        return -1


def extract_handshake(pcap_path: str) -> dict:
    """
    Parse a pcap/pcapng capture for a WPA 4-way handshake.
    Returns {ap_mac, sta_mac, anonce, snonce, eapol_msgs, pmkid, ssid, count}.
    """
    from scapy.all import rdpcap, Dot11, RadioTap

    result = {"ap_mac": "", "sta_mac": "", "anonce": "", "snonce": "",
              "pmkid": "", "eapol_msgs": [], "ssid": "", "count": 0}
    anonce, snonce, ap_mac, sta_mac = None, None, None, None
    ssid = ""

    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        return result

    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt.getlayer(Dot11)
        if d.type != 2:
            continue
        frame = bytes(pkt.getlayer(RadioTap).payload) if pkt.haslayer(RadioTap) else bytes(d)
        off = find_eapol_start(frame)
        if off < 0 or len(frame) < off + 4:
            continue
        eapol = frame[off:]
        if len(eapol) < 96:
            continue
        ver, typ = eapol[0], eapol[1]
        if typ != 0x03:  # 802.1X EAPOL-Key
            continue
        key_info = struct.unpack(">H", eapol[4:6])[0]
        replay = eapol[8:16]
        nonce = eapol[16:48]
        mic = eapol[80:96]
        key_data_len = struct.unpack(">H", eapol[96:98])[0]
        key_data = eapol[98:98 + key_data_len]
        # EAPOL-Key Key Information bit positions:
        #   install=bit4(0x0010) ack=bit5(0x0020) mic=bit6(0x0040)
        #   secure=bit7(0x0080) error=bit8(0x0100) request=bit9(0x0200)
        ack = bool(key_info & 0x0020)
        install = bool(key_info & 0x0010)
        mic_set = bool(key_info & 0x0040)
        secure = bool(key_info & 0x0080)

        src, dst = d.addr2, d.addr1
        if ack and not mic_set and install:  # msg 1 from AP
            ap_mac, anonce = src, nonce
            for pmkid_kde in _parse_pmkid(key_data):
                result["pmkid"] = pmkid_kde.hex()
        elif mic_set and not ack and not secure:  # msg 2 from STA
            sta_mac, snonce = src, nonce
        elif ack and mic_set:  # msg 3 from AP
            ap_mac, anonce = src, nonce
        elif mic_set and not ack and secure:  # msg 4 from STA
            sta_mac = src

        result["eapol_msgs"].append({
            "src": src, "dst": dst, "mic": mic.hex(),
            "key_info": hex(key_info), "replay": replay.hex(),
            "eapol_bytes": eapol.hex(),
        })

    if ap_mac:
        result["ap_mac"] = ap_mac
    if sta_mac:
        result["sta_mac"] = sta_mac
    if anonce:
        result["anonce"] = anonce.hex()
    if snonce:
        result["snonce"] = snonce.hex()
    result["count"] = len(result["eapol_msgs"])
    return result


def _parse_pmkid(key_data: bytes) -> list:
    """Extract PMKID KDE(s) (RSN element id 221, type 4)."""
    out = []
    i = 0
    while i + 2 <= len(key_data):
        eid, elen = key_data[i], key_data[i + 1]
        i += 2
        if i + elen > len(key_data):
            break
        info = key_data[i:i + elen]
        if eid == 221 and len(info) >= 20 and info[:4] == b"\x00\x0f\xac\x04":
            out.append(info[4:20])
        i += elen
    return out


# --------------------------------------------------------------------------
# AES-CCMP decryption of WPA2 data frames
# --------------------------------------------------------------------------

def _ccm_decrypt(tk: bytes, nonce: bytes, aad: bytes, data: bytes) -> tuple:
    """AES-CCM (L=2, M=8) decrypt. Returns (plaintext, mic_ok)."""
    mic_len = 8
    if len(data) < mic_len:
        return b"", False
    ciphertext = data[:-mic_len]
    tag_rx = data[-mic_len:]

    def aes_enc(b):
        return _aes_enc_block(tk, b)

    # S0 for MIC unmasking
    s0 = aes_enc(bytes([1]) + nonce + b"\x00\x00")

    # CTR decryption
    plain = bytearray()
    nblocks = (len(ciphertext) + 15) // 16
    for i in range(1, nblocks + 1):
        keystream = aes_enc(bytes([1]) + nonce + struct.pack(">H", i))
        chunk = ciphertext[(i - 1) * 16:i * 16]
        plain += bytes(x ^ y for x, y in zip(chunk, keystream))

    # CBC-MAC over B0 || AAD || message
    flags = 0x59  # L=2, M=8
    b0 = bytes([flags]) + nonce + struct.pack(">H", len(plain))
    blocks = [b0]
    if aad:
        aad_len = len(aad)
        first = struct.pack(">H", aad_len) if aad_len < 0xff00 else \
            struct.pack(">H", 0xfffe) + struct.pack(">I", aad_len)
        blocks.append(first + aad)
    payload = plain
    blocks.append(payload)

    x = b"\x00" * 16
    for blk in blocks:
        if blk:
            for i in range(0, len(blk), 16):
                chunk = blk[i:i + 16].ljust(16, b"\x00")
                x = aes_enc(bytes(a ^ b for a, b in zip(x, chunk)))
    tag = bytes(a ^ b for a, b in zip(x[:mic_len], s0[:mic_len]))
    ok = hmac.compare_digest(tag, tag_rx)
    return bytes(plain), ok


def ccmp_aad(frame: bytes) -> tuple:
    """
    Build CCMP AAD + locate header. Returns (aad, ccmp_hdr_offset, qos).
    frame = raw 802.11 frame (starting at Frame Control).
    """
    fc = struct.unpack("<H", frame[0:2])[0]
    qos = bool(frame[0] & 0x80) and (frame[0] & 0x0C) == 0x08
    fc_masked = (fc & 0x83FF) | (0x8000 if qos else 0)
    aad = bytearray()
    aad += struct.pack("<H", fc_masked)
    aad += frame[4:10]    # addr1
    aad += frame[10:16]   # addr2
    aad += frame[16:22]   # addr3
    seq = struct.unpack("<H", frame[22:24])[0] & 0xFFF0
    aad += struct.pack("<H", seq)
    hdr_len = 24
    if qos:
        aad += frame[24:26]
        hdr_len = 26
    return bytes(aad), hdr_len, qos


def decrypt_wpa2_frame(frame: bytes, ptk: bytes) -> bytes | None:
    """
    Decrypt a single captured WPA2 (CCMP) data frame using the PTK.
    Returns plaintext bytes or None if not decryptable.
    """
    if len(frame) < 32:
        return None
    aad, hdr_len, _ = ccmp_aad(frame)
    ccmp_hdr = frame[hdr_len:hdr_len + 8]
    if len(ccmp_hdr) < 8 or not (ccmp_hdr[0] & 0x20):
        return None  # not CCMP / WEP / TKIP
    pn = struct.unpack("<Q", ccmp_hdr[1:7] + b"\x00\x00")[0]
    nonce_pn = pn.to_bytes(6, "big")
    a2 = frame[10:16]
    nonce = b"\x00" + a2 + nonce_pn
    data = frame[hdr_len + 8:]
    tk = ptk[32:48]
    plain, ok = _ccm_decrypt(tk, nonce, aad, data)
    return plain if ok else None


def decrypt_wpa_capture(pcap_path: str, passphrase: str, ssid: str) -> dict:
    """
    High-level: extract handshake from pcap, derive PTK, decrypt every
    data frame. Returns {handshake, ptk, decrypted: [(src,dst,plaintext)]}.
    """
    from scapy.all import rdpcap, Dot11, RadioTap
    hs = extract_handshake(pcap_path)
    out = {"handshake": hs, "ptk": "", "decrypted": [], "failed": 0}
    if not (hs["ap_mac"] and hs["sta_mac"] and hs["anonce"] and hs["snonce"]):
        return out
    pmk = pbkdf2_psk(passphrase, ssid)
    ptk = derive_ptk(pmk, hs["ap_mac"], hs["sta_mac"],
                     bytes.fromhex(hs["anonce"]), bytes.fromhex(hs["snonce"]))
    out["ptk"] = ptk.hex()
    pkts = rdpcap(pcap_path)
    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt.getlayer(Dot11)
        if d.type != 2:
            continue
        frame = bytes(pkt.getlayer(RadioTap).payload) if pkt.haslayer(RadioTap) else bytes(d)
        plain = decrypt_wpa2_frame(frame, ptk)
        if plain:
            out["decrypted"].append({"src": d.addr2, "dst": d.addr1,
                                     "data": plain.hex()})
        else:
            out["failed"] += 1
    return out


# --------------------------------------------------------------------------
# Dictionary attack
# --------------------------------------------------------------------------

def crack_psk(passwords, ssid: str, handshake: dict) -> str | None:
    """Test each password against the extracted handshake. Returns match or None."""
    if not handshake.get("eapol_msgs"):
        return None
    # use first EAPOL frame carrying a MIC (msg 2/3/4)
    target = None
    for m in handshake["eapol_msgs"]:
        ki = int(m["key_info"], 16)
        if ki & 0x0040:  # MIC set (bit 6)
            target = m
            break
    if target is None:
        return None
    eapol = bytes.fromhex(target["eapol_bytes"])
    mic_rx = bytes.fromhex(target["mic"])
    pmkid_hex = handshake.get("pmkid") or ""
    ap_mac, sta_mac = handshake["ap_mac"], handshake["sta_mac"]
    anonce = bytes.fromhex(handshake["anonce"])
    snonce = bytes.fromhex(handshake["snonce"])

    for pw in passwords:
        pw = pw.rstrip("\r\n")
        pmk = pbkdf2_psk(pw, ssid)
        # fast PMKID pre-check
        if pmkid_hex:
            if pmkid(pmk, ap_mac, sta_mac).hex() != pmkid_hex:
                continue
            return pw
        ptk = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
        mic = compute_eapol_mic(ptk[0:16], eapol)
        if hmac.compare_digest(mic, mic_rx):
            return pw
    return None


def load_wordlist(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")