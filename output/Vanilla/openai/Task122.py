import os
import hashlib
import binascii

class UserStore:
    def __init__(self):
        self.store = {}

    def signup(self, username: str, password: str) -> bool:
        if username is None or password is None:
            return False
        if username in self.store:
            return False
        salt = os.urandom(16)
        salt_hex = binascii.hexlify(salt).decode()
        h = self._hash_password(password, salt)
        self.store[username] = f"{salt_hex}:{h}"
        return True

    def verify(self, username: str, password: str) -> bool:
        stored = self.store.get(username)
        if stored is None or password is None:
            return False
        salt_hex, hash_hex = stored.split(":", 1)
        salt = binascii.unhexlify(salt_hex.encode())
        actual = self._hash_password(password, salt)
        return self._constant_time_equals(hash_hex, actual)

    def get_stored(self, username: str):
        return self.store.get(username)

    def _hash_password(self, password: str, salt: bytes) -> str:
        h = hashlib.sha256()
        h.update(salt)
        h.update(password.encode("utf-8"))
        return h.hexdigest()

    def _constant_time_equals(self, a: str, b: str) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a.encode(), b.encode()):
            result |= x ^ y
        return result == 0

def main():
    us = UserStore()
    print("Test1 signup alice:", us.signup("alice", "Password123!"))
    print("Test2 signup bob:", us.signup("bob", "Secr3t!"))
    print("Test3 duplicate alice:", us.signup("alice", "another"))
    print("Test4 verify bob correct:", us.verify("bob", "Secr3t!"))
    print("Test5 verify bob wrong:", us.verify("bob", "wrong"))
    print("Stored alice:", us.get_stored("alice"))

if __name__ == "__main__":
    main()