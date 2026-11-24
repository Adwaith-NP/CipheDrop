"""Decode the QUIC Initial packets in a capture made by `make capture`.

QUIC protects Initial packets with keys derived from the client's
Destination Connection ID (RFC 9001, section 5.2), so anyone on the path
can read the ClientHello and ServerHello. This prints the TLS fields that
matter for the report (key share group, cipher suite, ALPN), the same
fields Wireshark shows, and counts the packets that stay encrypted.

Usage: python3 scripts/dev/decode-handshake.py docs/evidence/p1-handshake.pcap
Needs the Python `cryptography` package (pip install cryptography).
"""
import struct, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac, hashlib

SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
GROUPS = {0x11EC: "X25519MLKEM768", 0x001D: "x25519", 0x0017: "secp256r1"}
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}

def expand_label(secret, label, length):
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)

def keys(dcid, side):
    initial = hmac.new(SALT, dcid, hashlib.sha256).digest()
    s = expand_label(initial, side, 32)
    return expand_label(s, "quic key", 16), expand_label(s, "quic iv", 12), expand_label(s, "quic hp", 16)

def varint(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n

def packets(path):
    data = open(path, "rb").read()
    magic, = struct.unpack("<I", data[:4])
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    linktype, = struct.unpack(endian + "I", data[20:24])
    i = 24
    while i + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[i:i + 16])
        frame = data[i + 16:i + 16 + incl]
        i += 16 + incl
        if linktype == 1:      # Ethernet
            off = 14
        elif linktype == 113:  # Linux cooked v1
            off = 16
        elif linktype == 276:  # Linux cooked v2
            off = 20
        else:
            off = 0
        ip = frame[off:]
        if not ip or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 15) * 4
        src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
        sport, dport, ulen = struct.unpack(">HHH", ip[ihl:ihl + 6])
        yield src, sport, dst, dport, ip[ihl + 8:ihl + ulen]

def decrypt_initial(dg, dcid_for_keys, side):
    """Decrypt the first (Initial) packet of a datagram; returns (payload, dcid)."""
    b = bytearray(dg)
    if not b[0] & 0x80 or (b[0] & 0x30) >> 4 != 0:
        return None, None
    i = 5
    dl = b[i]; dcid = bytes(b[i + 1:i + 1 + dl]); i += 1 + dl
    sl = b[i]; i += 1 + sl
    tl, i = varint(b, i); i += tl
    length, i = varint(b, i)
    pn_off = i
    key, iv, hp = keys(dcid_for_keys or dcid, side)
    sample = bytes(b[pn_off + 4:pn_off + 20])
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    b[0] ^= mask[0] & 0x0F
    pn_len = (b[0] & 3) + 1
    for k in range(pn_len):
        b[pn_off + k] ^= mask[1 + k]
    pn = int.from_bytes(b[pn_off:pn_off + pn_len], "big")
    header = bytes(b[:pn_off + pn_len])
    ct = bytes(b[pn_off + pn_len:pn_off + length])
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    return AESGCM(key).decrypt(nonce, ct, header), dcid

def crypto_frames(payload):
    i, out = 0, []
    while i < len(payload):
        t = payload[i]
        if t == 0x00:            # PADDING
            i += 1
        elif t == 0x01:          # PING
            i += 1
        elif t == 0x02:          # ACK
            i += 1
            for _ in range(2):
                _, i = varint(payload, i)
            cnt, i = varint(payload, i)
            _, i = varint(payload, i)
            for _ in range(cnt * 2):
                _, i = varint(payload, i)
        elif t == 0x06:          # CRYPTO
            off, i = varint(payload, i + 1)
            ln, i = varint(payload, i)
            out.append((off, payload[i:i + ln]))
            i += ln
        else:
            break
    return out

def hello_fields(msg):
    typ = msg[0]
    body = msg[4:4 + int.from_bytes(msg[1:4], "big")]
    i = 2 + 32
    sid = body[i]; i += 1 + sid
    f = {"type": "ClientHello" if typ == 1 else "ServerHello"}
    if typ == 1:
        n, = struct.unpack(">H", body[i:i + 2]); f["suites"] = [struct.unpack(">H", body[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]; i += 2 + n
        n = body[i]; i += 1 + n
    else:
        f["suite"], = struct.unpack(">H", body[i:i + 2]); i += 3
    n, = struct.unpack(">H", body[i:i + 2]); i += 2
    end = i + n
    while i < end:
        et, el = struct.unpack(">HH", body[i:i + 4]); d = body[i + 4:i + 4 + el]; i += 4 + el
        if et == 51:
            if typ == 1:
                j = 2; shares = []
                while j < len(d):
                    g, kl = struct.unpack(">HH", d[j:j + 4]); shares.append((g, kl)); j += 4 + kl
                f["key_share"] = shares
            else:
                g, kl = struct.unpack(">HH", d[:4]); f["key_share"] = [(g, kl)]
        elif et == 10:
            f["groups"] = [struct.unpack(">H", d[2 + k:4 + k])[0] for k in range(0, struct.unpack(">H", d[:2])[0], 2)]
        elif et == 16:
            j = 2; names = []
            while j < len(d):
                ln = d[j]; names.append(d[j + 1:j + 1 + ln].decode()); j += 1 + ln
            f["alpn"] = names
        elif et == 43:
            f["versions"] = [struct.unpack(">H", d[1 + k:3 + k])[0] for k in range(0, d[0], 2)] if typ == 1 else [struct.unpack(">H", d)[0]]
        elif et == 42:
            f["early_data"] = True
    return f

pk = list(packets(sys.argv[1]))
first = pk[0]
client, server = (first[0], first[1]), (first[2], first[3])
odcid = None; chunks = {"client in": [], "server in": []}; sizes = []
protected = 0
for src, sport, dst, dport, dg in pk:
    side = "client in" if (src, sport) == client else "server in"
    if dg[0] & 0x80 and (dg[0] & 0x30) == 0:
        try:
            pl, dcid = decrypt_initial(dg, odcid, side)
        except Exception:
            pl = None
        if pl is not None:
            if odcid is None:
                odcid = dcid
            cf = crypto_frames(pl)
            chunks[side] += cf
            if cf:
                sizes.append((side, len(dg)))
            continue
    protected += 1

def assemble(parts):
    buf = bytearray()
    for off, d in sorted(parts):
        if off == len(buf):
            buf += d
    return bytes(buf)

ch = hello_fields(assemble(chunks["client in"]))
sh = hello_fields(assemble(chunks["server in"]))
ci = [s for s in sizes if s[0] == "client in"]
print(f"Capture: {sys.argv[1].split('/')[-1]}   {len(pk)} UDP datagrams   {client[0]}:{client[1]} -> {server[0]}:{server[1]}")
print(f"QUIC Initial packets carrying the ClientHello: {len(ci)} (sizes {', '.join(str(s[1]) for s in ci)} bytes)")
print("TLSv1.3 Record: Handshake Protocol: Client Hello")
print("    Supported Versions: " + ", ".join("TLS 1.3 (0x%04x)" % v for v in ch.get("versions", [])))
print("    Cipher Suites: " + ", ".join(SUITES.get(s, "0x%04x" % s) for s in ch["suites"]))
print("    Supported Groups: " + ", ".join("%s (0x%04x)" % (GROUPS.get(g, "?"), g) for g in ch.get("groups", [])))
for g, kl in ch.get("key_share", []):
    print("    Key Share Entry: Group: %s (0x%04x), Key Exchange length: %d" % (GROUPS.get(g, "?"), g, kl))
print("    ALPN Protocol: " + ", ".join(ch.get("alpn", [])))
print("    Early data (0-RTT): " + ("offered" if ch.get("early_data") else "not offered"))
print("TLSv1.3 Record: Handshake Protocol: Server Hello")
print("    Cipher Suite: %s (0x%04x)" % (SUITES.get(sh["suite"], "?"), sh["suite"]))
for g, kl in sh.get("key_share", []):
    print("    Key Share Entry: Group: %s (0x%04x), Key Exchange length: %d" % (GROUPS.get(g, "?"), g, kl))
print(f"Remaining {protected} datagrams: QUIC Handshake / 1-RTT packets, payload encrypted (no plaintext visible)")
