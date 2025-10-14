# Requires: pip install cryptography
# Secure storage with AES-256-GCM and PBKDF2-HMAC-SHA256

import os
import base64
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import pbkdf2_hmac

class Task124:
    @staticmethod
    def _serialize(data: Dict[str, str]) -> bytes:
        out_lines = []
        for k, v in data.items():
            kb = base64.b64encode(k.encode("utf-8")).decode("ascii")
            vb = base64.b64encode(v.encode("utf-8")).decode("ascii")
            out_lines.append(f"{kb}={vb}")
        return ("\n".join(out_lines) + "\n").encode("utf-8")

    @staticmethod
    def _deserialize(b: bytes) -> Dict[str, str]:
        s = b.decode("utf-8")
        out: Dict[str, str] = {}
        for line in s.splitlines():
            if not line:
                continue
            if "=" not in line:
                continue
            kb, vb = line.split("=", 1)
            k = base64.b64decode(kb.encode("ascii")).decode("utf-8")
            v = base64.b64decode(vb.encode("ascii")).decode("utf-8")
            out[k] = v
        return out

    @staticmethod
    def _kdf(password: str, salt: bytes, iterations: int = 200_000, key_len: int = 32) -> bytes:
        return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=key_len)

    @staticmethod
    def encrypt(data: Dict[str, str], password: str) -> bytes:
        salt = os.urandom(16)
        key = Task124._kdf(password, salt)
        iv = os.urandom(12)
        aead = AESGCM(key)
        aad = b"SVLTv1"
        ct = aead.encrypt(iv, Task124._serialize(data), aad)
        # blob: magic(4) + ver(1) + saltLen(1) + ivLen(1) + salt + iv + ct
        blob = b"SVLT" + bytes([1, len(salt), len(iv)]) + salt + iv + ct
        return blob

    @staticmethod
    def decrypt(blob: bytes, password: str) -> Dict[str, str]:
        if len(blob) < 7:
            raise ValueError("Blob too short")
        if blob[:4] != b"SVLT":
            raise ValueError("Invalid blob")
        ver = blob[4]
        if ver != 1:
            raise ValueError("Unsupported version")
        salt_len = blob[5]
        iv_len = blob[6]
        idx = 7
        salt = blob[idx:idx+salt_len]; idx += salt_len
        iv = blob[idx:idx+iv_len]; idx += iv_len
        ct = blob[idx:]
        key = Task124._kdf(password, salt)
        aead = AESGCM(key)
        aad = b"SVLTv1"
        pt = aead.decrypt(iv, ct, aad)
        return Task124._deserialize(pt)

    @staticmethod
    def save_to_file(data: bytes, filename: str) -> None:
        with open(filename, "wb") as f:
            f.write(data)

    @staticmethod
    def load_from_file(filename: str) -> bytes:
        with open(filename, "rb") as f:
            return f.read()

if __name__ == "__main__":
    # 5 test cases
    cases = [
        ({"cardNumber": "4111111111111111", "cardHolder": "ALICE A", "expiry": "12/29"}, "StrongPass#1", "vault1_py.bin"),
        ({"ssn": "123-45-6789", "name": "Bob B"}, "StrongPass#2", "vault2_py.bin"),
        ({"email": "carol@example.com", "dob": "1990-07-15", "address": "123 Main St"}, "StrongPass#3", "vault3_py.bin"),
        ({"passport": "X12345678", "country": "Wonderland"}, "StrongPass#4", "vault4_py.bin"),
        ({"apiKey": "sk_test_51Hk...", "note": "Rotate regularly"}, "StrongPass#5", "vault5_py.bin"),
    ]
    for i, (data, pwd, fname) in enumerate(cases, 1):
        blob = Task124.encrypt(data, pwd)
        Task124.save_to_file(blob, fname)
        loaded = Task124.load_from_file(fname)
        recovered = Task124.decrypt(loaded, pwd)
        print(f"Test{i}:", recovered)