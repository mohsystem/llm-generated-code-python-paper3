import os
import hmac
import hashlib
import secrets

class Task42:
    def __init__(self):
        self.users = {}

    def register_user(self, username: str, password: str) -> bool:
        if username in self.users:
            return False
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
        self.users[username] = (salt, pwd_hash)
        return True

    def authenticate(self, username: str, password: str) -> bool:
        entry = self.users.get(username)
        if not entry:
            return False
        salt, stored = entry
        test = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
        return hmac.compare_digest(stored, test)

if __name__ == "__main__":
    auth = Task42()
    print(auth.register_user("alice", "password123"))  # Test 1
    print(auth.register_user("bob", "S3cur3!"))        # Test 2
    print(auth.register_user("alice", "another"))      # Test 3 (duplicate)
    print(auth.authenticate("alice", "password123"))   # Test 4
    print(auth.authenticate("alice", "wrong"))         # Test 5