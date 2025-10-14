import secrets
import base64
import time
from typing import Dict, Optional, List

class Task134:
    class KeyRecord:
        __slots__ = ("id", "algorithm", "bits", "exportable", "created_at", "key_material")
        def __init__(self, kid: str, algorithm: str, bits: int, exportable: bool, key_material: bytearray):
            self.id = kid
            self.algorithm = algorithm
            self.bits = bits
            self.exportable = exportable
            self.created_at = int(time.time())
            self.key_material = key_material

    class KeyManager:
        def __init__(self):
            self._store: Dict[str, Task134.KeyRecord] = {}

        @staticmethod
        def _generate_id() -> str:
            return secrets.token_hex(16)

        @staticmethod
        def _secure_wipe(barr: Optional[bytearray]) -> None:
            if barr is None:
                return
            for i in range(len(barr)):
                barr[i] = 0

        def create_symmetric_key(self, algorithm: str, bits: int, exportable: bool) -> str:
            if algorithm is None or algorithm.upper() != "AES":
                raise ValueError("Unsupported algorithm")
            if bits not in (128, 192, 256):
                raise ValueError("Invalid key size")
            key_bytes = bits // 8
            material = bytearray(secrets.token_bytes(key_bytes))
            kid = self._generate_id()
            rec = Task134.KeyRecord(kid, "AES", bits, exportable, material)
            self._store[kid] = rec
            return kid

        def get_key_info(self, key_id: str) -> Optional[str]:
            rec = self._store.get(key_id)
            if rec is None:
                return None
            return '{{"id":"{}","algorithm":"{}","bits":{},"exportable":{},"createdAt":{}}}'.format(
                rec.id, rec.algorithm, rec.bits, str(rec.exportable).lower(), rec.created_at
            )

        def list_key_ids(self) -> List[str]:
            return list(self._store.keys())

        def delete_key(self, key_id: str) -> bool:
            rec = self._store.pop(key_id, None)
            if rec is None:
                return False
            self._secure_wipe(rec.key_material)
            return True

        def rotate_key(self, key_id: str) -> bool:
            rec = self._store.get(key_id)
            if rec is None:
                return False
            old = rec.key_material
            try:
                rec.key_material = bytearray(secrets.token_bytes(rec.bits // 8))
                return True
            finally:
                self._secure_wipe(old)

        def export_key_base64(self, key_id: str) -> Optional[str]:
            rec = self._store.get(key_id)
            if rec is None or not rec.exportable:
                return None
            return base64.b64encode(bytes(rec.key_material)).decode("ascii")

    # Testable wrapper functions as required
    @staticmethod
    def create_key(km: "Task134.KeyManager", algorithm: str, bits: int, exportable: bool) -> str:
        return km.create_symmetric_key(algorithm, bits, exportable)

    @staticmethod
    def get_key_info(km: "Task134.KeyManager", key_id: str) -> Optional[str]:
        return km.get_key_info(key_id)

    @staticmethod
    def rotate_key(km: "Task134.KeyManager", key_id: str) -> bool:
        return km.rotate_key(key_id)

    @staticmethod
    def delete_key(km: "Task134.KeyManager", key_id: str) -> bool:
        return km.delete_key(key_id)

    @staticmethod
    def export_key(km: "Task134.KeyManager", key_id: str) -> Optional[str]:
        return km.export_key_base64(key_id)

    @staticmethod
    def list_keys(km: "Task134.KeyManager") -> List[str]:
        return km.list_key_ids()


if __name__ == "__main__":
    km = Task134.KeyManager()

    # Test case 1: Create exportable AES-256 key
    id1 = Task134.create_key(km, "AES", 256, True)
    print("Test1 id1:", id1)
    print("Info1:", Task134.get_key_info(km, id1))

    # Test case 2: Create non-exportable AES-128 key
    id2 = Task134.create_key(km, "AES", 128, False)
    print("Test2 id2:", id2)
    print("Info2:", Task134.get_key_info(km, id2))

    # Test case 3: List keys
    print("Test3 list:", Task134.list_keys(km))

    # Test case 4: Export id1 and attempt export id2
    exp1 = Task134.export_key(km, id1)
    print("Test4a export id1 length:", len(exp1) if exp1 else -1)
    exp2 = Task134.export_key(km, id2)
    print("Test4b export id2 should be None:", exp2)

    # Test case 5: Rotate id1 and delete id2
    print("Test5a rotate id1:", Task134.rotate_key(km, id1))
    print("Test5b delete id2:", Task134.delete_key(km, id2))
    print("Info2 after delete:", Task134.get_key_info(km, id2))