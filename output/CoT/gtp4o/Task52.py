# Chain-of-Through process:
# 1) Problem: Encrypt/decrypt files using AES-GCM; parameters as inputs; return/raise on errors; include tests.
# 2) Security: AES-256-GCM, 96-bit random nonce, authenticated encryption, secure randomness.
# 3) Secure coding: Use cryptography AESGCM, avoid static IVs, handle errors, no key hardcoding.
# 4) Review: Ensure IV prepended, tag included, verify decryption, safe file handling.
# 5) Output: Final implemented functions and tests.

import os
import secrets
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise RuntimeError("Requires 'cryptography' package") from e


def generate_key(bits: int = 256) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192, or 256 bits")
    return secrets.token_bytes(bits // 8)


def encrypt_file(key: bytes, input_path: str, output_path: str) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length")
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    with open(input_path, "rb") as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)  # ct includes tag internally
    with open(output_path, "wb") as f:
        f.write(nonce + ct)


def decrypt_file(key: bytes, input_path: str, output_path: str) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length")
    with open(input_path, "rb") as f:
        blob = f.read()
    if len(blob) < 12 + 16:
        raise ValueError("Invalid input: too short")
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    with open(output_path, "wb") as f:
        f.write(pt)


def files_equal(path1: str, path2: str) -> bool:
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        a = f1.read()
        b = f2.read()
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= (x ^ y)
    return diff == 0


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def main() -> None:
    key = generate_key(256)
    tmp = os.getenv("TMPDIR") or os.getenv("TEMP") or "/tmp"
    tests = [
        b"",
        b"Hello, AES-GCM!",
        "Unicode: こんにちは世界🌍".encode("utf-8"),
        bytes(1024),
        secrets.token_bytes(4096),
    ]
    all_ok = True
    for i, data in enumerate(tests):
        in_path = os.path.join(tmp, f"py_in_{i}.bin")
        enc_path = os.path.join(tmp, f"py_enc_{i}.bin")
        out_path = os.path.join(tmp, f"py_out_{i}.bin")
        _write_bytes(in_path, data)
        try:
            encrypt_file(key, in_path, enc_path)
            decrypt_file(key, enc_path, out_path)
            ok = files_equal(in_path, out_path)
            all_ok &= ok
        finally:
            for p in (in_path, enc_path, out_path):
                try:
                    os.remove(p)
                except OSError:
                    pass
    print("Python tests passed" if all_ok else "Python tests failed")


if __name__ == "__main__":
    main()