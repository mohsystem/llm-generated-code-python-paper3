import base64
import secrets
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    raise

def _u32(v: int) -> bytes:
    return v.to_bytes(4, 'big', signed=False)

def _encode_string(b: bytes) -> bytes:
    return _u32(len(b)) + b

def _mpint_from_int(x: int) -> bytes:
    if x == 0:
        return _encode_string(b'')
    length = (x.bit_length() + 7) // 8
    raw = x.to_bytes(length, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return _encode_string(raw)

def _build_public_blob(n: int, e: int) -> bytes:
    out = b''
    out += _encode_string(b'ssh-rsa')
    out += _mpint_from_int(e)
    out += _mpint_from_int(n)
    return out

def _build_private_blob(n: int, e: int, d: int, iqmp: int, p: int, q: int, comment: str) -> bytes:
    out = b''
    check = secrets.randbits(32)
    out += _u32(check)
    out += _u32(check)
    out += _encode_string(b'ssh-rsa')
    out += _mpint_from_int(n)
    out += _mpint_from_int(e)
    out += _mpint_from_int(d)
    out += _mpint_from_int(iqmp)
    out += _mpint_from_int(p)
    out += _mpint_from_int(q)
    out += _encode_string(comment.encode('utf-8'))
    # padding to blocksize 8
    block = 8
    pad_len = (block - (len(out) % block)) % block
    if pad_len:
        out += bytes((i for i in range(1, pad_len + 1)))
    return out

def _wrap_b64(s: str, width: int = 70) -> str:
    return '\n'.join(s[i:i+width] for i in range(0, len(s), width))

def generate_openssh_rsa_private_key(bits: int, comment: str = "") -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    numbers = key.private_numbers()
    pub = numbers.public_numbers
    n = pub.n
    e = pub.e
    d = numbers.d
    p = numbers.p
    q = numbers.q
    iqmp = numbers.iqmp

    pub_blob = _build_public_blob(n, e)
    priv_blob = _build_private_blob(n, e, d, iqmp, p, q, comment)

    data = b"openssh-key-v1\0"
    data += _encode_string(b'none')
    data += _encode_string(b'none')
    data += _encode_string(b'')  # kdfoptions
    data += _u32(1)  # number of keys
    data += _encode_string(pub_blob)
    data += _encode_string(priv_blob)

    b64 = base64.b64encode(data).decode('ascii')
    wrapped = _wrap_b64(b64, 70)
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrapped + "\n-----END OPENSSH PRIVATE KEY-----\n"

if __name__ == "__main__":
    print(generate_openssh_rsa_private_key(2048, "py-test-1"))
    print(generate_openssh_rsa_private_key(1024, "py-test-2"))
    print(generate_openssh_rsa_private_key(3072, "py-test-3"))
    print(generate_openssh_rsa_private_key(4096, "py-test-4"))
    print(generate_openssh_rsa_private_key(1536, "py-test-5"))