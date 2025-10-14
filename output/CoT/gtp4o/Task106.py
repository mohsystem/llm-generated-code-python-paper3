import secrets
from typing import Tuple

# Step 1: Problem understanding - RSA basic operations

def _egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic bases for 64-bit would be fixed; for larger use random bases
    bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]  # OK up to 2^64; still fine as probable for larger
    for a in bases:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                skip = True
                break
        if not skip:
            return False
    return True

def _random_odd_bits(bits: int) -> int:
    x = secrets.randbits(bits)
    x |= (1 << (bits - 1))  # ensure MSB set
    x |= 1  # make odd
    return x

def _gen_prime(bits: int) -> int:
    while True:
        cand = _random_odd_bits(bits)
        if _is_probable_prime(cand):
            return cand

# Step 2+3: Security requirements + Secure coding generation

def generate_keys(bits: int) -> Tuple[int, int, int]:
    if bits < 512:
        raise ValueError("Key size too small; use at least 512 bits")
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        if _egcd(e, phi)[0] != 1:
            continue
        d = _modinv(e, phi)
        return (n, e, d)

def encrypt(message: int, e: int, n: int) -> int:
    if message < 0 or message >= n:
        raise ValueError("Message out of range")
    return pow(message, e, n)

def decrypt(ciphertext: int, d: int, n: int) -> int:
    if ciphertext < 0 or ciphertext >= n:
        raise ValueError("Ciphertext out of range")
    return pow(ciphertext, d, n)

def string_to_int(s: str) -> int:
    return int.from_bytes(s.encode('utf-8'), 'big', signed=False)

def int_to_string(x: int) -> str:
    if x == 0:
        return ""
    blen = (x.bit_length() + 7) // 8
    return x.to_bytes(blen, 'big', signed=False).decode('utf-8')

# Step 4: Code review - ensured bounds and checks
# Step 5: Secure code output - main tests

def main():
    n, e, d = generate_keys(1024)
    tests = [
        "Hello RSA",
        "Test 123",
        "Secure message",
        "Data 4",
        "Fifth test!"
    ]
    for i, msg in enumerate(tests, 1):
        m = string_to_int(msg)
        if m >= n:
            print(f"Test {i}: message too large for modulus")
            continue
        c = encrypt(m, e, n)
        p = decrypt(c, d, n)
        rec = int_to_string(p)
        print(f"Test {i}:")
        print(f"  Message: {msg}")
        print(f"  Cipher (hex): {hex(c)}")
        print(f"  Decrypted: {rec}")
        print(f"  OK: {rec == msg}")

if __name__ == "__main__":
    main()