import os
import time
import hmac
import hashlib
import base64
from typing import Dict

class Task133:
    TOKEN_TTL_SECONDS = 15 * 60
    PBKDF2_ITERATIONS = 150_000
    SALT_LEN = 16
    DK_LEN = 32

    COMMON_PASSWORDS = {
        "password", "123456", "123456789", "qwerty", "111111",
        "12345678", "abc123", "password1", "1234567", "12345",
        "letmein", "admin", "welcome", "monkey", "login"
    }

    class User:
        def __init__(self, email: str, pass_hash: str):
            self.email = email
            self.pass_hash = pass_hash  # format: pbkdf2$sha256$iter$saltB64$hashB64
            self.reset_token_hash_hex = None
            self.reset_token_expiry = 0

    def __init__(self):
        self.users: Dict[str, Task133.User] = {}

    # API
    def register_user(self, email: str, password: str) -> bool:
        if not email or not password:
            return False
        email = email.lower()
        if not self._is_strong_password(password, email):
            return False
        if email in self.users:
            return False
        self.users[email] = Task133.User(email, self._hash_password(password))
        return True

    def request_password_reset(self, email: str) -> str:
        email_l = (email or "").lower()
        token = self._generate_token()
        token_hash_hex = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expiry = int(time.time()) + self.TOKEN_TTL_SECONDS
        user = self.users.get(email_l)
        if user:
            user.reset_token_hash_hex = token_hash_hex
            user.reset_token_expiry = expiry
        return token

    def reset_password(self, email: str, token: str, new_password: str) -> bool:
        if not email or not token or not new_password:
            return False
        email_l = email.lower()
        user = self.users.get(email_l)
        if not user:
            return False
        now = int(time.time())
        if not user.reset_token_hash_hex or now > user.reset_token_expiry:
            return False
        provided_hash_hex = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(user.reset_token_hash_hex, provided_hash_hex):
            return False
        if not self._is_strong_password(new_password, email_l):
            return False
        if self._verify_password(new_password, user.pass_hash):
            return False
        user.pass_hash = self._hash_password(new_password)
        user.reset_token_hash_hex = None
        user.reset_token_expiry = 0
        return True

    def verify_login(self, email: str, password: str) -> bool:
        if not email or not password:
            return False
        user = self.users.get(email.lower())
        if not user:
            return False
        return self._verify_password(password, user.pass_hash)

    # Helpers
    def _is_strong_password(self, password: str, email: str) -> bool:
        if len(password) < 12:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        if not (has_upper and has_lower and has_digit and has_symbol):
            return False
        if password.lower() in self.COMMON_PASSWORDS:
            return False
        if email:
            user_part = email.split("@")[0]
            if user_part and user_part.lower() in password.lower():
                return False
        return True

    def _hash_password(self, password: str) -> str:
        salt = os.urandom(self.SALT_LEN)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, self.PBKDF2_ITERATIONS, dklen=self.DK_LEN)
        salt_b64 = base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii")
        hash_b64 = base64.urlsafe_b64encode(dk).rstrip(b"=").decode("ascii")
        return f"pbkdf2$sha256${self.PBKDF2_ITERATIONS}${salt_b64}${hash_b64}"

    def _verify_password(self, password: str, stored: str) -> bool:
        try:
            algo, h, iter_s, salt_b64, hash_b64 = stored.split("$")
            if algo != "pbkdf2" or h != "sha256":
                return False
            iterations = int(iter_s)
            salt = base64.urlsafe_b64decode(salt_b64 + "===")
            expected = base64.urlsafe_b64decode(hash_b64 + "===")
            got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
            return hmac.compare_digest(expected, got)
        except Exception:
            return False

    def _generate_token(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")

if __name__ == "__main__":
    t = Task133()
    print("Register Alice:", t.register_user("alice@example.com", "InitialPassw0rd!"))
    print("Register Bob:  ", t.register_user("bob@example.com", "Secur3P@ssw0rd!"))
    print("Register Charlie:", t.register_user("charlie@example.com", "Another$tr0ng1"))
    print("Register Dave:", t.register_user("dave@example.com", "Y3t@Str0ngPass!"))
    print("Register Eve: ", t.register_user("eve@example.com", "InitialPassw0rd!"))

    # 1) Successful reset
    tok1 = t.request_password_reset("alice@example.com")
    r1 = t.reset_password("alice@example.com", tok1, "NewStrongP@ssw0rd!")
    print("Test1 success reset:", r1, "| login new:", t.verify_login("alice@example.com", "NewStrongP@ssw0rd!"))

    # 2) Expired token
    tok2 = t.request_password_reset("bob@example.com")
    # Simulate expiry
    t.users["bob@example.com"].reset_token_expiry = int(time.time()) - 1
    r2 = t.reset_password("bob@example.com", tok2, "AnotherN3wP@ss!")
    print("Test2 expired token result:", r2)

    # 3) Weak password attempt
    tok3 = t.request_password_reset("charlie@example.com")
    r3 = t.reset_password("charlie@example.com", tok3, "password")
    print("Test3 weak password result:", r3)

    # 4) Invalid token
    t.request_password_reset("dave@example.com")
    r4 = t.reset_password("dave@example.com", "INVALID_TOKEN", "Th!sIsStr0ngP@ss")
    print("Test4 invalid token result:", r4)

    # 5) Reuse old password not allowed
    tok5 = t.request_password_reset("eve@example.com")
    r5 = t.reset_password("eve@example.com", tok5, "InitialPassw0rd!")
    print("Test5 reuse old password result:", r5)