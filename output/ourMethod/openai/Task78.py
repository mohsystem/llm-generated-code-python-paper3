import base64
import secrets
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except Exception as _e:  # pragma: no cover
    raise SystemExit("cryptography module is required")


def _u32(v: int) -> bytes:
    return v.to_bytes(4, "big", signed=False)


def _write_string(b: bytearray, data: bytes) -> None:
    b += _u32(len(data))
    b += data


def _mpint(i: int) -> bytes:
    if i == 0:
        return _u32(0)
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        data = b"\x00" + raw
    else:
        data = raw
    return _u32(len(data)) + data


def _public_key_blob(e: int, n: int) -> bytes:
    b = bytearray()
    _write_string(b, b"ssh-rsa")
    b += _mpint(e)
    b += _mpint(n)
    return bytes(b)


def _private_block(n: int, e: int, d: int, iqmp: int, p: int, q: int, comment: str) -> bytes:
    b = bytearray()
    check = secrets.randbits(32)
    b += _u32(check)
    b += _u32(check)
    _write_string(b, b"ssh-rsa")
    b += _mpint(n)
    b += _mpint(e)
    b += _mpint(d)
    b += _mpint(iqmp)
    b += _mpint(p)
    b += _mpint(q)
    _write_string(b, comment.encode("utf-8"))

    pad_len = 8 - (len(b) % 8)
    if pad_len == 0:
        pad_len = 8
    for i in range(1, pad_len + 1):
        b.append(i & 0xFF)
    return bytes(b)


def generate_openssh_rsa_private_key(bits: int, comment: str) -> str:
    if bits < 2048 or bits > 8192:
        raise ValueError("bits must be between 2048 and 8192")
    if comment is None:
        comment = ""
    if len(comment) > 1024:
        raise ValueError("comment too long")

    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    numbers = priv.private_numbers()
    pub = numbers.public_numbers

    pub_blob = _public_key_blob(pub.e, pub.n)
    priv_block = _private_block(numbers.public_numbers.n, numbers.public_numbers.e, numbers.d, numbers.iqmp, numbers.p, numbers.q, comment)

    out = bytearray()
    out += b"openssh-key-v1\0"
    _write_string(out, b"none")      # ciphername
    _write_string(out, b"none")      # kdfname
    _write_string(out, b"")          # kdfoptions
    out += _u32(1)                   # number of keys
    _write_string(out, pub_blob)     # public keys
    _write_string(out, priv_block)   # private block

    b64 = base64.b64encode(bytes(out)).decode("ascii")
    # Wrap at 70 chars per line
    wrapped = "\n".join(b64[i:i+70] for i in range(0, len(b64), 70))
    header = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    footer = "-----END OPENSSH PRIVATE KEY-----\n"
    return header + wrapped + "\n" + footer


def _test():
    tests = [
        (2048, "test1"),
        (2048, "user@example"),
        (3072, "device-key"),
        (4096, "backup"),
        (2048, "prod-key"),
    ]
    for i, (bits, comment) in enumerate(tests, 1):
        key = generate_openssh_rsa_private_key(bits, comment)
        print(f"Case {i}: generated={key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----')}, bits={bits}, length={len(key)}")


if __name__ == "__main__":
    _test()