from __future__ import annotations
from typing import ByteString
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def generate_salt(length: int = 16) -> bytes:
    if length <= 0 or length > 1024:
        raise ValueError("Invalid salt length.")
    return token_bytes(length)


def is_password_strong(password: str) -> bool:
    if password is None or len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special


def hash_password(password: str, salt: ByteString, iterations: int = 210_000, dk_len: int = 32) -> str:
    if not password:
        raise ValueError("Password must not be empty.")
    if not is_password_strong(password):
        raise ValueError("Password does not meet strength policy.")
    if salt is None or len(salt) < 8 or len(salt) > 1024:
        raise ValueError("Invalid salt.")
    if iterations < 100_000 or iterations > 5_000_000:
        raise ValueError("Invalid iterations.")
    if dk_len < 16 or dk_len > 64:
        raise ValueError("Invalid derived key length.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=dk_len,
        salt=bytes(salt),
        iterations=iterations,
    )
    dk = kdf.derive(password.encode("utf-8"))
    return dk.hex()


if __name__ == "__main__":
    passwords = [
        "Str0ngPassw0rd!",
        "An0ther$ecurePwd",
        "C0mpl3x#Pass123",
        "S@feAndS0und2025",
        "R0bust_P@ssw0rd!!",
    ]
    for i, pw in enumerate(passwords, 1):
        salt = generate_salt(16)
        h = hash_password(pw, salt)
        print(f"Test {i} hash: {h}")