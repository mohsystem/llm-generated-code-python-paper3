import os
import sys
from pathlib import Path
from typing import Tuple
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

MAGIC = b"ENC1"
VERSION = 1
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
PBKDF2_ITERATIONS = 210_000
KEY_LEN = 32

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError("Invalid inputs")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_to_bytes(passphrase: str, data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Data must be bytes")
    salt = token_bytes(SALT_LEN)
    iv = token_bytes(IV_LEN)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(iv, data, None)
    if len(ct_tag) < TAG_LEN:
        raise ValueError("Encryption failed")
    ciphertext, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    return MAGIC + bytes([VERSION]) + salt + iv + ciphertext + tag

def decrypt_from_bytes(passphrase: str, blob: bytes) -> bytes:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < len(MAGIC)+1+SALT_LEN+IV_LEN+TAG_LEN:
        raise ValueError("Invalid blob")
    if blob[:4] != MAGIC:
        raise ValueError("Bad magic")
    version = blob[4]
    if version != VERSION:
        raise ValueError("Unsupported version")
    salt = blob[5:5+SALT_LEN]
    iv = blob[5+SALT_LEN:5+SALT_LEN+IV_LEN]
    rest = blob[5+SALT_LEN+IV_LEN:]
    if len(rest) < TAG_LEN:
        raise ValueError("Invalid blob content")
    ciphertext, tag = rest[:-TAG_LEN], rest[-TAG_LEN:]
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, None)

def _resolve_safe_path(base_dir: str, user_relative_path: str) -> Path:
    base = Path(base_dir).resolve()
    if not user_relative_path or user_relative_path.startswith(("/", "\\")) or ".." in user_relative_path:
        raise ValueError("Invalid relative path")
    target = (base / user_relative_path).resolve()
    if not str(target).startswith(str(base) + os.sep) and target != base:
        raise ValueError("Path escapes base directory")
    # Reject symlink final component if exists
    if target.exists() and target.is_symlink():
        raise ValueError("Symlink not allowed")
    # Ensure no parent is a symlink
    for parent in target.parents:
        if parent == parent.anchor:
            break
        if parent.exists() and parent.is_symlink():
            raise ValueError("Symlink in path not allowed")
    return target

def save_encrypted(base_dir: str, user_relative_path: str, passphrase: str, data: bytes) -> bool:
    try:
        target = _resolve_safe_path(base_dir, user_relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        blob = encrypt_to_bytes(passphrase, data)
        tmp_path = target.with_suffix(target.suffix + ".tmp")
        with open(tmp_path, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
        return True
    except Exception:
        return False

def load_decrypted(base_dir: str, user_relative_path: str, passphrase: str) -> bytes:
    target = _resolve_safe_path(base_dir, user_relative_path)
    with open(target, "rb") as f:
        blob = f.read()
    return decrypt_from_bytes(passphrase, blob)

def _random_passphrase(nbytes: int = 16) -> str:
    return token_bytes(nbytes).hex()

def main() -> None:
    base = "secure_store_py"
    files = ["rec1.bin", "rec2.bin", "rec3.bin", "rec4.bin", "rec5.bin"]
    passphrases = [_random_passphrase() for _ in range(5)]
    records = [
        b"User: Alice; CC: 4111-1111-1111-1111; Exp: 12/29",
        b"User: Bob; SSN: 123-45-6789; DOB: 1990-01-01",
        b"User: Carol; Passport: X12345678; Country: US",
        b"User: Dave; Bank: 0123456789; Routing: 021000021",
        b"User: Eve; Email: eve@example.com; Phone: +1-555-0100",
    ]
    for i in range(5):
        ok = save_encrypted(base, files[i], passphrases[i], records[i])
        if not ok:
            print(f"Test {i+1} save failed")
            continue
        dec = load_decrypted(base, files[i], passphrases[i])
        print(f"Test {i+1} {'OK' if dec == records[i] else 'mismatch'}")

if __name__ == "__main__":
    main()