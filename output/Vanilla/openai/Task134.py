import base64
import secrets

class KeyManager:
    def __init__(self):
        self._store = {}

    def generate_key(self, alias: str, length_bytes: int) -> bool:
        if not alias or length_bytes <= 0 or alias in self._store:
            return False
        self._store[alias] = secrets.token_bytes(length_bytes)
        return True

    def export_key_base64(self, alias: str):
        key = self._store.get(alias)
        if key is None:
            return None
        return base64.b64encode(key).decode('ascii')

    def import_key_base64(self, alias: str, b64: str, overwrite: bool) -> bool:
        if not alias or b64 is None:
            return False
        if (not overwrite) and (alias in self._store):
            return False
        try:
            raw = base64.b64decode(b64.encode('ascii'), validate=True)
            if len(raw) == 0:
                return False
            self._store[alias] = raw
            return True
        except Exception:
            return False

    def rotate_key(self, alias: str, new_length_bytes: int):
        if alias not in self._store or new_length_bytes <= 0:
            return None
        self._store[alias] = secrets.token_bytes(new_length_bytes)
        return base64.b64encode(self._store[alias]).decode('ascii')

    def delete_key(self, alias: str) -> bool:
        return self._store.pop(alias, None) is not None

    def list_aliases(self) -> str:
        return ",".join(self._store.keys())

    def get_key_length(self, alias: str) -> int:
        key = self._store.get(alias)
        return -1 if key is None else len(key)

def main():
    km = KeyManager()

    # Test 1
    t1gen = km.generate_key("api", 32)
    t1exp = km.export_key_base64("api")
    print("T1 gen=", t1gen, " len=", km.get_key_length("api"), " b64prefix=", (None if t1exp is None else t1exp[:10]))

    # Test 2
    t2gen = km.generate_key("db", 16)
    print("T2 gen=", t2gen, " aliases=", km.list_aliases())

    # Test 3
    exported = km.export_key_base64("api")
    t3imp = km.import_key_base64("imported", exported, False)
    print("T3 import=", t3imp, " importedLen=", km.get_key_length("imported"))

    # Test 4
    t4rot = km.rotate_key("api", 24)
    print("T4 rotatedLen=", km.get_key_length("api"), " rotB64prefix=", (None if t4rot is None else t4rot[:10]))

    # Test 5
    t5del = km.delete_key("db")
    print("T5 delete=", t5del, " aliases=", km.list_aliases())

if __name__ == "__main__":
    main()