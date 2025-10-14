from typing import List, Optional

DELTA = 0x9E3779B9

def encrypt(plaintext: str, key_hex: str) -> str:
    if plaintext is None or key_hex is None:
        return ""
    k = _parse_hex_key(key_hex)
    if k is None:
        return ""
    data = plaintext.encode("utf-8")
    if len(data) == 0:
        return ""
    v = _to_uint32_array(data, include_length=True)
    _xxtea_encrypt(v, k)
    out = _to_byte_array(v, include_length=False)
    return _bytes_to_hex(out)

def decrypt(cipher_hex: str, key_hex: str) -> str:
    if cipher_hex is None or key_hex is None:
        return ""
    k = _parse_hex_key(key_hex)
    if k is None:
        return ""
    enc = _hex_to_bytes(cipher_hex)
    if enc is None or len(enc) == 0:
        return ""
    v = _to_uint32_array(enc, include_length=False)
    if len(v) == 0:
        return ""
    _xxtea_decrypt(v, k)
    out = _to_byte_array(v, include_length=True)
    if out is None:
        return ""
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return ""

def _parse_hex_key(key_hex: str) -> Optional[List[int]]:
    s = key_hex.strip()
    if len(s) != 32:
        return None
    kb = _hex_to_bytes(s)
    if kb is None or len(kb) != 16:
        return None
    k = []
    for i in range(4):
        j = i * 4
        w = (kb[j] |
             (kb[j+1] << 8) |
             (kb[j+2] << 16) |
             (kb[j+3] << 24)) & 0xFFFFFFFF
        k.append(w)
    return k

def _to_uint32_array(data: bytes, include_length: bool) -> List[int]:
    n = (len(data) + 3) >> 2
    size = n + 1 if include_length else (n if n > 0 else 1)
    v = [0] * size
    for i, b in enumerate(data):
        v[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
        v[i >> 2] &= 0xFFFFFFFF
    if include_length:
        v[-1] = len(data) & 0xFFFFFFFF
    return v

def _to_byte_array(v: List[int], include_length: bool) -> Optional[bytes]:
    n = len(v) << 2
    m = n
    if include_length:
        if len(v) == 0:
            return b""
        length = v[-1]
        if length < 0 or length > n:
            return None
        m = length
    out = bytearray(m)
    for i in range(m):
        out[i] = (v[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)

def _xxtea_encrypt(v: List[int], k: List[int]) -> None:
    n = len(v)
    if n < 2:
        return
    rounds = 6 + 52 // n
    total = 0
    z = v[-1]
    while rounds > 0:
        rounds -= 1
        total = (total + DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(0, n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF)) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        mx = (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF)) ^ ((total ^ y) + (k[((n - 1) & 3) ^ e] ^ z))
        v[-1] = (v[-1] + (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
        z = v[-1]

def _xxtea_decrypt(v: List[int], k: List[int]) -> None:
    n = len(v)
    if n < 2:
        return
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & 0xFFFFFFFF
    z = v[-1]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ ((v[p] << 2) & 0xFFFFFFFF)) + (((v[p] >> 3) ^ ((z << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF)) ^ ((total ^ v[p]) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
        y = v[0]
        mx = (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF)) ^ ((total ^ y) + (k[(0 & 3) ^ e] ^ z))
        v[0] = (v[0] - (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
        z = v[-1]
        total = (total - DELTA) & 0xFFFFFFFF

def _bytes_to_hex(data: bytes) -> str:
    return ''.join(f'{b:02x}' for b in data)

def _hex_to_bytes(s: str) -> Optional[bytes]:
    s = s.strip()
    if len(s) % 2 != 0:
        return None
    try:
        return bytes(int(s[i:i+2], 16) for i in range(0, len(s), 2))
    except ValueError:
        return None

if __name__ == "__main__":
    key = "00112233445566778899aabbccddeeff"
    tests = [
        "",
        "hello",
        "The quick brown fox jumps over the lazy dog.",
        "1234567890",
        "Sensitive data!"
    ]
    for t in tests:
        enc = encrypt(t, key)
        dec = decrypt(enc, key)
        print("PT:", t)
        print("CT:", enc)
        print("DC:", dec)
        print("----")