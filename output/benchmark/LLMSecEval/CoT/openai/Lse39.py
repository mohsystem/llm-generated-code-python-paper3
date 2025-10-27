# Chain-of-Through Steps applied: secure hashing, constant-time compare, input validation.
# Language: Python
# Includes a main section with 5 test cases.

import hashlib
import hmac

USER_SALT = "usr_salt_v1|"
PASS_SALT = "pwd_salt_v1|"
EXPECTED_USERNAME = "admin"
EXPECTED_PASSWORD = "Password!234"
MAX_LEN = 64

def _sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def _sha256_of_str(s: str) -> bytes:
    return _sha256_bytes(s.encode("utf-8"))

def login(username: str, password: str) -> str:
    if username is None or password is None:
        return "Incorrect username or password."
    if len(username) == 0 or len(password) == 0:
        return "Incorrect username or password."
    if len(username) > MAX_LEN or len(password) > MAX_LEN:
        return "Incorrect username or password."

    provided_user_hash = _sha256_of_str(USER_SALT + username)
    expected_user_hash = _sha256_of_str(USER_SALT + EXPECTED_USERNAME)

    provided_pass_hash = _sha256_of_str(PASS_SALT + password)
    expected_pass_hash = _sha256_of_str(PASS_SALT + EXPECTED_PASSWORD)

    user_ok = hmac.compare_digest(provided_user_hash, expected_user_hash)
    pass_ok = hmac.compare_digest(provided_pass_hash, expected_pass_hash)

    if user_ok and pass_ok:
        return "Login successful. Redirecting to /session"
    else:
        return "Incorrect username or password."

if __name__ == "__main__":
    tests = [
        ("admin", "Password!234"),             # correct
        ("admin", "Password!2345"),            # wrong password
        ("Admin", "Password!234"),             # wrong username (case)
        ("user", "123"),                       # both wrong
        ("admin", "a" * 65),                   # too long
    ]
    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {u} / <hidden> -> {login(u, p)}")