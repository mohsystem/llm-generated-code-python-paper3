from __future__ import annotations
import base64
from typing import ByteString
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
import secrets
import sys


def encrypt(passphrase: str, plaintext: ByteString) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM with a key derived from the passphrase via PBKDF2-HMAC-SHA256.
    Returns blob: b"ENC1" + bytes([1]) + salt(16) + iv(12) + ciphertext||tag(16)
    """
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Invalid passphrase")
    if plaintext is None:
        raise ValueError("Invalid plaintext")
    data = bytes(plaintext)
    if len(data) > 50_000_000:
        raise ValueError("Plaintext too large")

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=210_000,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, data, None)  # ciphertext || 16-byte tag

    blob = b"ENC1" + bytes([1]) + salt + iv + ct

    # Best-effort key wipe (Python may keep copies due to immutability/GC)
    # Overwrite local variable references
    key = b"\x00" * len(key)

    return blob


def _print_b64(blob: bytes) -> None:
    print(base64.b64encode(blob).decode("ascii"))


def main() -> None:
    try:
        c1 = encrypt("correct horse battery staple", b"Hello, world!")
        c2 = encrypt("Tr0ub4dor&3", b"Security-focused encryption using AES-256-GCM.")
        c3 = encrypt("another strong passphrase", "短いメッセージ".encode("utf-8"))
        c4 = encrypt("Yet-Another-Secret", b"1234567890")
        c5 = encrypt("SufficientlyLongAndComplexPassphrase!", b"The quick brown fox jumps over the lazy dog.")

        _print_b64(c1)
        _print_b64(c2)
        _print_b64(c3)
        _print_b64(c4)
        _print_b64(c5)
    except Exception:
        print("Encryption failed")


if __name__ == "__main__":
    # Avoid unbounded recursion or environment-dependent behavior
    sys.setrecursionlimit(10000)
    main()