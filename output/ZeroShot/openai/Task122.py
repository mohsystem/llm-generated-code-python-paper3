import base64
import hashlib
import hmac
import secrets
import re

class Task122:
    class UserStore:
        def __init__(self):
            self._store = {}
            self._iterations = 200_000
            self._salt_len = 16
            self._dk_len = 32
            self._user_re = re.compile(r"^[A-Za-z0-9_]{3,32}$")

        def _validate_password(self, password: str):
            if password is None:
                return "Null password."
            if len(password) < 12:
                return "Password too short (min 12)."
            hasU = any(c.isupper() for c in password)
            hasL = any(c.islower() for c in password)
            hasD = any(c.isdigit() for c in password)
            hasS = any((not c.isalnum()) and (not c.isspace()) for c in password)
            if not (hasU and hasL and hasD and hasS):
                return "Password must include upper, lower, digit, and symbol."
            return None

        def signup(self, username: str, password: str) -> str:
            if username is None or password is None:
                return "ERROR: Null input."
            if not self._user_re.fullmatch(username or ""):
                return "ERROR: Invalid username."
            pwerr = self._validate_password(password)
            if pwerr:
                return f"ERROR: {pwerr}"
            if username in self._store:
                return "ERROR: Username already exists."
            salt = secrets.token_bytes(self._salt_len)
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, self._iterations, dklen=self._dk_len
            )
            rec = f"pbkdf2_sha256${self._iterations}$" + \
                  base64.b64encode(salt).decode() + "$" + \
                  base64.b64encode(dk).decode()
            self._store[username] = rec
            # Best effort cleanup
            del dk
            return "SUCCESS"

        def get_record(self, username: str):
            return self._store.get(username)

def main():
    us = Task122.UserStore()
    print(us.signup("alice", "StrongPassw0rd!"))
    print(us.get_record("alice"))
    print(us.signup("bob", "short"))
    print(us.signup("invalid user", "AnotherStrong1!"))
    print(us.signup("alice", "AnotherStrong1!"))
    print(us.signup("carol_123", "C0mplEx#Passw0rd"))
    print(us.get_record("carol_123"))

if __name__ == "__main__":
    main()