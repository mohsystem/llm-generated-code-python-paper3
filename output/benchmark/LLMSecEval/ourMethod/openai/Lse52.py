import os
import re
import secrets
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass
class Credential:
    salt: bytes
    hash: bytes
    iterations: int

def index_page() -> str:
    return '<!doctype html><html><head><meta charset="utf-8"></head><body><h1>Welcome</h1><a href="/login">Login</a></body></html>'

def login_page() -> str:
    return '<!doctype html><html><head><meta charset="utf-8"></head><body><h1>Login</h1><form action="/do_login" method="post">Username: <input type="text" name="username" maxlength="32" /><br/>Password: <input type="password" name="password" maxlength="128" /><br/><button type="submit">Login</button></form></body></html>'

def secret_page(session: Dict[str, str]) -> str:
    if session.get("username"):
        return '<!doctype html><html><head><meta charset="utf-8"></head><body>Secret settings</body></html>'
    return '<!doctype html><html><head><meta charset="utf-8"></head><body>Unauthorized</body></html>'

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    return re.fullmatch(r"[A-Za-z0-9_-]+", username) is not None

def is_valid_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    return 12 <= len(password) <= 128

def pbkdf2_sha256(password: str, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def create_credential(password: str, iterations: int = 210_000) -> Credential:
    salt = secrets.token_bytes(16)
    pw_hash = pbkdf2_sha256(password, salt, iterations, 32)
    return Credential(salt=salt, hash=pw_hash, iterations=iterations)

def verify_password(password: str, cred: Credential) -> bool:
    if cred is None or password is None:
        return False
    candidate = pbkdf2_sha256(password, cred.salt, cred.iterations, len(cred.hash))
    return constant_time_equals(candidate, cred.hash)

def do_login(session: Dict[str, str], username: str, password: str, users: Dict[str, Credential]) -> str:
    if session is None or users is None:
        return "ERROR:Invalid session/store"
    if not is_valid_username(username):
        return "ERROR:Invalid username"
    if not is_valid_password(password):
        return "ERROR:Invalid password"
    cred = users.get(username)
    if cred is None or not verify_password(password, cred):
        return "ERROR:Invalid credentials"
    session["username"] = username
    return "REDIRECT:/secret"

def _random_password(n: int) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(n))

def main():
    users: Dict[str, Credential] = {}
    username = "alice"
    password = _random_password(14)  # Not printed
    users[username] = create_credential(password)

    session: Dict[str, str] = {}

    passed = 0
    total = 5

    # Test 1: Success
    r1 = do_login(session, username, password, users)
    t1 = (r1 == "REDIRECT:/secret" and session.get("username") == username and "Secret settings" in secret_page(session))
    if t1:
        passed += 1
    session.clear()

    # Test 2: Wrong password
    r2 = do_login(session, username, "WrongPassword123!", users)
    t2 = r2.startswith("ERROR:") and "username" not in session
    if t2:
        passed += 1

    # Test 3: Wrong username
    r3 = do_login(session, "bob", password, users)
    t3 = r3.startswith("ERROR:") and "username" not in session
    if t3:
        passed += 1

    # Test 4: Invalid username format
    r4 = do_login(session, "bad<user>", password, users)
    t4 = r4.startswith("ERROR:Invalid username")
    if t4:
        passed += 1

    # Test 5: Password too short
    r5 = do_login(session, username, "shortPwd1!", users)
    t5 = r5.startswith("ERROR:Invalid password")
    if t5:
        passed += 1

    print("Index page sample:", "OK" if "Login" in index_page() else "FAIL")
    print("Login page sample:", "OK" if "form" in login_page() else "FAIL")
    print(f"Tests passed: {passed}/{total}")

if __name__ == "__main__":
    main()