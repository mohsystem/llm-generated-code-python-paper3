import secrets
import sys

class RSAKey:
    __slots__ = ("n", "e", "d")
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d

def _egcd(a: int, b: int):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def _is_probable_prime(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    # small primes quick check
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = secrets.randbits(bits)
        # set MSB and LSB to ensure size and oddness
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate

def _lcm(a: int, b: int) -> int:
    from math import gcd
    return a // gcd(a, b) * b

def generate_key(bits: int = 2048) -> RSAKey:
    if bits < 512:
        raise ValueError("bits must be >= 512")
    e = 65537
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        phi = _lcm(p - 1, q - 1)
        if phi % e == 0:
            continue
        d = _modinv(e, phi)
        return RSAKey(n, e, d)

def _i2osp(x: int, x_len: int) -> bytes:
    if x < 0 or x >= 1 << (8 * x_len):
        raise ValueError("integer too large")
    return x.to_bytes(x_len, byteorder="big")

def _os2ip(x: bytes) -> int:
    return int.from_bytes(x, byteorder="big", signed=False)

def encrypt(message: bytes, e: int, n: int) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    m = _os2ip(message)
    if m >= n:
        raise ValueError("Message too long for the modulus")
    c = pow(m, e, n)
    k = (n.bit_length() + 7) // 8
    return _i2osp(c, k)

def decrypt(ciphertext: bytes, d: int, n: int) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    c = _os2ip(ciphertext)
    if c >= n:
        raise ValueError("Ciphertext representative out of range")
    m = pow(c, d, n)
    # Return minimal-length bytes (strip leading zeros)
    out = m.to_bytes((m.bit_length() + 7) // 8 or 1, byteorder="big")
    # If message was empty, represent as b""
    if m == 0:
        return b""
    return out

def _run_tests():
    # Use 1024-bit for faster test runs; use 2048+ in real use.
    key = generate_key(1024)
    tests = [
        "Hello RSA!",
        "",
        "The quick brown fox jumps over the lazy dog",
        "1234567890",
        "🔒 RSA Test 🚀",
    ]
    ok_count = 0
    for i, t in enumerate(tests, 1):
        msg = t.encode("utf-8")
        ct = encrypt(msg, key.e, key.n)
        pt = decrypt(ct, key.d, key.n)
        recovered = pt.decode("utf-8")
        passed = recovered == t
        print(f"Test {i}: {'OK' if passed else 'FAIL'}")
        ok_count += 1 if passed else 0
    return ok_count

if __name__ == "__main__":
    _run_tests()