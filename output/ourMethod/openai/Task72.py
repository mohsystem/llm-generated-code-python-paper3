from __future__ import annotations
from typing import List
from secrets import token_bytes, compare_digest
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"ENC1"
VERSION = bytes([1])
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
ITERATIONS = 210_000
KEY_LEN = 32


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError("Invalid inputs to KDF")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(passphrase: str, plaintext: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("Plaintext must be bytes")
    if not isinstance(passphrase, str):
        raise ValueError("Passphrase must be str")

    salt = token_bytes(SALT_LEN)
    iv = token_bytes(IV_LEN)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, bytes(plaintext), None)  # ciphertext || tag
    return MAGIC + VERSION + salt + iv + ct


def decrypt(passphrase: str, blob: bytes) -> bytes:
    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError("Input must be bytes")
    blob = bytes(blob)
    min_len = len(MAGIC) + 1 + SALT_LEN + IV_LEN + TAG_LEN
    if len(blob) < min_len:
        raise ValueError("Input too short")

    if blob[:4] != MAGIC:
        raise ValueError("Bad magic")
    if blob[4:5] != VERSION:
        raise ValueError("Unsupported version")

    salt = blob[5:5 + SALT_LEN]
    iv = blob[5 + SALT_LEN:5 + SALT_LEN + IV_LEN]
    ct = blob[5 + SALT_LEN + IV_LEN:]
    if len(ct) < TAG_LEN:
        raise ValueError("Ciphertext too short")

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct, None)


def _ct_equal(a: bytes, b: bytes) -> bool:
    return compare_digest(a, b)


def main() -> None:
    passphrase = "correct horse battery staple"
    tests: List[bytes] = [
        b"Hello, World!",
        b"",
        b"The quick brown fox jumps over the lazy dog",
        b"0" * 1000,
        "Unicode \u03c0 \U0001F680".encode("utf-8"),
    ]
    for i, pt in enumerate(tests, 1):
        enc = encrypt(passphrase, pt)
        dec = decrypt(passphrase, enc)
        ok = _ct_equal(pt, dec)
        print(f"Test {i}: {'OK' if ok else 'FAIL'} encSize={len(enc)}")


if __name__ == "__main__":
    main()