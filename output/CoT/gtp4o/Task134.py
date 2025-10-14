import secrets
import hmac
import hashlib
import time
from typing import Dict, Optional, List

# High-level notes:
# - In-memory key manager using secrets for CSPRNG.
# - Keys are stored as bytearray and zeroized on deletion or rotation.
# - Provides HMAC-SHA256 sign/verify using the managed keys.

class KeyRecord:
    def __init__(self, label: str, version: int, key: bytearray):
        self.label = label
        self.version = version
        self.key = key
        self.created_at_ms = int(time.time() * 1000)

class KeyManager:
    def __init__(self):
        self._store: Dict[str, KeyRecord] = {}

    def create_key(self, label: str, size_bytes: int = 32) -> int:
        if not label:
            raise ValueError("label must not be empty")
        if size_bytes < 16:
            raise ValueError("key size too small")
        if label in self._store:
            return self._store[label].version
        key = bytearray(secrets.token_bytes(size_bytes))
        self._store[label] = KeyRecord(label, 1, key)
        return 1

    def get_key_copy(self, label: str) -> Optional[bytes]:
        rec = self._store.get(label)
        if rec is None or rec.key is None:
            return None
        return bytes(rec.key)

    def rotate_key(self, label: str, size_bytes: int = 32) -> int:
        if size_bytes < 16:
            raise ValueError("key size too small")
        rec = self._store.get(label)
        if rec is None:
            raise KeyError("label not found")
        new_key = bytearray(secrets.token_bytes(size_bytes))
        self._zeroize(rec.key)
        rec.key = new_key
        rec.version += 1
        return rec.version

    def delete_key(self, label: str) -> bool:
        rec = self._store.pop(label, None)
        if rec is None:
            return False
        self._zeroize(rec.key)
        return True

    def list_keys(self) -> List[str]:
        return sorted([f"{rec.label}:v{rec.version}" for rec in self._store.values()])

    def sign_hmac(self, label: str, message: bytes) -> bytes:
        rec = self._store.get(label)
        if rec is None or rec.key is None:
            raise KeyError("label not found")
        return hmac.new(bytes(rec.key), message, hashlib.sha256).digest()

    def verify_hmac(self, label: str, message: bytes, tag: bytes) -> bool:
        rec = self._store.get(label)
        if rec is None or rec.key is None:
            return False
        calc = hmac.new(bytes(rec.key), message, hashlib.sha256).digest()
        return hmac.compare_digest(calc, tag)

    @staticmethod
    def _zeroize(barr: Optional[bytearray]) -> None:
        if barr is None:
            return
        for i in range(len(barr)):
            barr[i] = 0

def _to_hex(b: Optional[bytes]) -> str:
    if b is None:
        return "null"
    return b.hex()

def main():
    km = KeyManager()

    # Test 1: create 'alpha' and list
    v1 = km.create_key("alpha", 32)
    print("Created alpha v", v1, " keys=", km.list_keys())

    # Test 2: sign/verify with 'alpha'
    msg = b"hello world"
    tag1 = km.sign_hmac("alpha", msg)
    print("tag1=", _to_hex(tag1), " verify=", km.verify_hmac("alpha", msg, tag1))

    # Test 3: rotate 'alpha' and sign again; old tag should fail to verify
    v2 = km.rotate_key("alpha", 32)
    tag2 = km.sign_hmac("alpha", msg)
    print("Rotated alpha to v", v2, " tag2=", _to_hex(tag2), " old_ok=", km.verify_hmac("alpha", msg, tag1))

    # Test 4: create 'beta' and list
    km.create_key("beta", 32)
    print("Keys now:", km.list_keys())

    # Test 5: delete 'alpha' and check
    print("Deleted alpha?", km.delete_key("alpha"), " get=", km.get_key_copy("alpha"))

if __name__ == "__main__":
    main()