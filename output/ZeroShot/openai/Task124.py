import os
import stat
import sys
import secrets
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

MAGIC = b"TSK1"
SALT_LEN = 16
IV_LEN = 12
PBKDF2_ITERS = 200_000
KEY_LEN = 32  # 256-bit
AAD = MAGIC

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    iv = secrets.token_bytes(IV_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, AAD)
    out = MAGIC + salt + iv + ct
    # best-effort wiping
    if isinstance(plaintext, bytearray):
        for i in range(len(plaintext)):
            plaintext[i] = 0
    return out

def decrypt(blob: bytes, password: str) -> bytes:
    if len(blob) < len(MAGIC) + SALT_LEN + IV_LEN + 16:
        raise ValueError("Invalid blob")
    off = 0
    magic = blob[off:off+len(MAGIC)]; off += len(MAGIC)
    if magic != MAGIC:
        raise ValueError("Invalid header")
    salt = blob[off:off+SALT_LEN]; off += SALT_LEN
    iv = blob[off:off+IV_LEN]; off += IV_LEN
    ct = blob[off:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct, AAD)

def store_to_file(sensitive_data: str, password: str, path: str) -> None:
    pt = sensitive_data.encode("utf-8")
    blob = encrypt(pt, password)
    dirn = os.path.dirname(path) or "."
    tmp = os.path.join(dirn, os.path.basename(path) + ".tmp-" + secrets.token_hex(6))
    with open(tmp, "wb") as f:
        try:
            # Restrictive permissions (best effort)
            try:
                os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR)
            except AttributeError:
                pass
            f.write(blob)
        finally:
            # wipe blob
            ba = bytearray(blob)
            for i in range(len(ba)):
                ba[i] = 0
            del ba
    try:
        os.replace(tmp, path)
    except Exception:
        # Cleanup tmp on failure
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

def load_from_file(password: str, path: str) -> str:
    with open(path, "rb") as f:
        blob = f.read()
    pt = decrypt(blob, password)
    try:
        return pt.decode("utf-8")
    finally:
        ba = bytearray(pt)
        for i in range(len(ba)):
            ba[i] = 0
        del ba

def _flip_one_byte(path: str) -> None:
    with open(path, "rb") as f:
        data = bytearray(f.read())
    if len(data) > len(MAGIC) + SALT_LEN + IV_LEN + 16:
        idx = len(data) - 1 - secrets.randbelow(min(32, max(1, len(data) - (len(MAGIC) + SALT_LEN + IV_LEN))))
        data[idx] ^= 0x01
    with open(path, "wb") as f:
        f.write(data)
    for i in range(len(data)):
        data[i] = 0

if __name__ == "__main__":
    try:
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="task124-securestore-")
        f1 = os.path.join(tmpdir, "cc1.bin")
        f2 = os.path.join(tmpdir, "pii2.bin")
        f3 = os.path.join(tmpdir, "wrongpass.bin")
        f4 = os.path.join(tmpdir, "tamper.bin")
        f5 = os.path.join(tmpdir, "unicode.bin")

        # Test 1
        t1 = "cc=4111111111111111;exp=12/28;cvc=123;name=Jane Doe"
        p1 = "StrongPassw0rd!"
        store_to_file(t1, p1, f1)
        r1 = load_from_file(p1, f1)
        print("Test1 OK:", len(r1) == len(t1))

        # Test 2
        t2 = "name=John Doe;ssn=123-45-6789;dob=1970-01-01;addr=123 Main St"
        p2 = "An0ther$trongPass"
        store_to_file(t2, p2, f2)
        r2 = load_from_file(p2, f2)
        print("Test2 OK:", len(r2) == len(t2))

        # Test 3: Wrong password
        t3 = "email=jane@example.com;phone=+1-555-555-5555"
        p3 = "CorrectHorseBatteryStaple!"
        store_to_file(t3, p3, f3)
        try:
            load_from_file("TotallyWrongPassword", f3)
            print("Test3 Wrong Password Rejected:", False)
        except Exception:
            print("Test3 Wrong Password Rejected:", True)

        # Test 4: Tamper detection
        t4 = "passport=Z12345678;country=US;expiry=2030-12-31"
        p4 = "TamperProofKey#2024"
        store_to_file(t4, p4, f4)
        _flip_one_byte(f4)
        try:
            load_from_file(p4, f4)
            print("Test4 Tampering Detected:", False)
        except Exception:
            print("Test4 Tampering Detected:", True)

        # Test 5: Unicode
        t5 = "name=Мария;note=机密情報🔒;extra="
        p5 = "Un1c0de-安全-كلمهسر"
        store_to_file(t5, p5, f5)
        r5 = load_from_file(p5, f5)
        print("Test5 OK:", len(r5) == len(t5))

    except Exception as e:
        print("Error:", type(e).__name__)