from __future__ import annotations
from typing import Tuple
import sys
import hmac
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENC1"
VERSION = bytes([1])
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
ITERATIONS = 210_000
KEY_LEN = 32  # 256-bit


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError("Invalid input")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str) -> bytes:
    if not isinstance(plaintext, str) or not isinstance(passphrase, str):
        raise ValueError("Invalid input")
    salt = token_bytes(SALT_LEN)
    iv = token_bytes(IV_LEN)
    key = _derive_key(passphrase, salt)
    aead = AESGCM(key)
    pt = plaintext.encode("utf-8")
    ct_and_tag = aead.encrypt(iv, pt, None)
    if len(ct_and_tag) < TAG_LEN:
        raise ValueError("Encryption failure")
    ct = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]
    return MAGIC + VERSION + salt + iv + ct + tag


def decrypt(blob: bytes, passphrase: str) -> str:
    if not isinstance(blob, (bytes, bytearray)) or not isinstance(passphrase, str):
        raise ValueError("Invalid input")
    min_len = len(MAGIC) + 1 + SALT_LEN + IV_LEN + TAG_LEN
    if len(blob) < min_len:
        raise ValueError("Decryption failed")
    pos = 0
    if not hmac.compare_digest(blob[pos:pos + len(MAGIC)], MAGIC):
        raise ValueError("Decryption failed")
    pos += len(MAGIC)
    version = blob[pos:pos + 1]
    pos += 1
    if version != VERSION:
        raise ValueError("Decryption failed")
    salt = blob[pos:pos + SALT_LEN]
    pos += SALT_LEN
    iv = blob[pos:pos + IV_LEN]
    pos += IV_LEN
    remaining = len(blob) - pos
    if remaining < TAG_LEN:
        raise ValueError("Decryption failed")
    ct = blob[pos:pos + remaining - TAG_LEN]
    tag = blob[pos + len(ct):pos + len(ct) + TAG_LEN]
    key = _derive_key(passphrase, salt)
    aead = AESGCM(key)
    pt = aead.decrypt(iv, ct + tag, None)
    return pt.decode("utf-8")


def _run_tests() -> None:
    tests = [
        "",
        "hello",
        "The quick brown fox jumps over the lazy dog.",
        "Numbers 1234567890!@#",
        "Repeat message repeat message repeat message."
    ]
    passphrase = "Strong Passphrase 2025!"
    ok = 0
    for i, t in enumerate(tests, 1):
        try:
            blob = encrypt(t, passphrase)
            dec = decrypt(blob, passphrase)
            if hmac.compare_digest(t.encode("utf-8"), dec.encode("utf-8")):
                print(f"Test {i} OK")
                ok += 1
            else:
                print(f"Test {i} FAIL")
        except Exception:
            print(f"Test {i} FAIL")
    if ok != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    _run_tests()