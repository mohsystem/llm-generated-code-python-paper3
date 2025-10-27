import os
import hmac
import hashlib
import secrets

class SecureAuth:
    def __init__(self):
        self._db = {}  # username -> (salt_bytes, hash_bytes)

    def add_user(self, username: str, password: str) -> bool:
        if not username or password is None:
            return False
        if username in self._db:
            return False
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000, dklen=32)
        self._db[username] = (salt, dk)
        return True

    def login(self, username: str, password: str) -> str:
        if not username or password is None:
            return "/login"
        rec = self._db.get(username)
        if not rec:
            return "/login"
        salt, stored = rec
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000, dklen=32)
        return "/dashboard" if hmac.compare_digest(computed, stored) else "/login"

def main():
    auth = SecureAuth()
    auth.add_user("alice", "Correct$Horse1")
    auth.add_user("bob", "S3curePass!")

    print(auth.login("alice", "Correct$Horse1"))  # /dashboard
    print(auth.login("alice", "wrongpass"))       # /login
    print(auth.login("unknown", "whatever"))      # /login
    print(auth.login("", ""))                     # /login
    print(auth.login("bob", "S3curePass!"))       # /dashboard

if __name__ == "__main__":
    main()