import base64
import os
import struct
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except Exception:
    rsa = None
    default_backend = None

def _put_uint32(buf: bytearray, v: int) -> None:
    buf.extend(struct.pack(">I", v & 0xFFFFFFFF))

def _put_string_bytes(buf: bytearray, b: bytes) -> None:
    _put_uint32(buf, len(b))
    buf.extend(b)

def _put_string(buf: bytearray, s: str) -> None:
    _put_string_bytes(buf, s.encode("utf-8"))

def _mpint_bytes(x: int) -> bytes:
    if x == 0:
        return b""
    # minimal two's complement, positive
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    # trim redundant leading zeros (keep one if next has high bit set)
    while len(b) > 1 and b[0] == 0x00 and (b[1] & 0x80) == 0:
        b = b[1:]
    return b

def _put_mpint(buf: bytearray, x: int) -> None:
    b = _mpint_bytes(x)
    _put_string_bytes(buf, b)

def _build_public_blob(n: int, e: int) -> bytes:
    buf = bytearray()
    _put_string(buf, "ssh-rsa")
    _put_mpint(buf, e)
    _put_mpint(buf, n)
    return bytes(buf)

def _build_private_blob(n: int, e: int, d: int, iqmp: int, p: int, q: int, comment: str) -> bytes:
    buf = bytearray()
    check = struct.unpack(">I", os.urandom(4))[0]
    _put_uint32(buf, check)
    _put_uint32(buf, check)
    _put_string(buf, "ssh-rsa")
    _put_mpint(buf, n)
    _put_mpint(buf, e)
    _put_mpint(buf, d)
    _put_mpint(buf, iqmp)
    _put_mpint(buf, p)
    _put_mpint(buf, q)
    _put_string(buf, comment)

    block = 8
    pad_len = block - (len(buf) % block)
    if pad_len == 0:
        pad_len = block
    for i in range(1, pad_len + 1):
        buf.append(i & 0xFF)
    return bytes(buf)

def generate_openssh_rsa_private_key(key_size: int, comment: str) -> str:
    if rsa is None:
        raise RuntimeError("cryptography library is required for RSA key generation")

    ks = max(2048, int(key_size))
    priv = rsa.generate_private_key(public_exponent=65537, key_size=ks, backend=default_backend())
    nums = priv.private_numbers()
    pub = nums.public_numbers

    n = pub.n
    e = pub.e
    d = nums.d
    p = nums.p
    q = nums.q
    iqmp = nums.iqmp  # q^{-1} mod p

    outer = bytearray()
    outer.extend(b"openssh-key-v1\0")
    _put_string(outer, "none")         # ciphername
    _put_string(outer, "none")         # kdfname
    _put_string_bytes(outer, b"")      # kdfoptions
    _put_uint32(outer, 1)              # number of keys

    pub_blob = _build_public_blob(n, e)
    _put_string_bytes(outer, pub_blob)

    prv_blob = _build_private_blob(n, e, d, iqmp, p, q, comment or "")
    _put_string_bytes(outer, prv_blob)

    b64 = base64.b64encode(bytes(outer)).decode("ascii")
    lines = ["-----BEGIN OPENSSH PRIVATE KEY-----"]
    for i in range(0, len(b64), 70):
        lines.append(b64[i:i+70])
    lines.append("-----END OPENSSH PRIVATE KEY-----")
    return "\n".join(lines)

if __name__ == "__main__":
    # 5 test cases
    print(generate_openssh_rsa_private_key(2048, "test1"))
    print()
    print(generate_openssh_rsa_private_key(3072, "user@example.com"))
    print()
    print(generate_openssh_rsa_private_key(4096, "case3"))
    print()
    print(generate_openssh_rsa_private_key(1024, "auto-upgraded-to-2048"))
    print()
    print(generate_openssh_rsa_private_key(2048, ""))