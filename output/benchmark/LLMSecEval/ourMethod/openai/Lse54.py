import os
import sys
import re
import hmac
import hashlib
import secrets

MIN_USERNAME_LEN = 1
MAX_USERNAME_LEN = 64
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128

_SALT = secrets.token_bytes(16)
_expected_hash = None
_expected_user = None

def login() -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Login</title></head>"
        "<body><h1>Login</h1>"
        "<form method=\"POST\" action=\"/do_login\">"
        "<label>Username: <input type=\"text\" name=\"username\" maxlength=\"64\" required></label><br>"
        "<label>Password: <input type=\"password\" name=\"password\" minlength=\"12\" maxlength=\"128\" required></label><br>"
        "<button type=\"submit\">Login</button>"
        "</form></body></html>"
    )

def _valid_username(u: str) -> bool:
    if u is None:
        return False
    if not (MIN_USERNAME_LEN <= len(u) <= MAX_USERNAME_LEN):
        return False
    # ASCII only, allow alnum and _.-@
    return re.fullmatch(r"[A-Za-z0-9_.\-@]{1,64}", u) is not None

def _valid_password_policy(p: str) -> bool:
    if p is None or not (MIN_PASSWORD_LEN <= len(p) <= MAX_PASSWORD_LEN):
        return False
    if any(ord(ch) > 0x7F for ch in p):
        return False
    has_upper = any(c.isupper() for c in p)
    has_lower = any(c.islower() for c in p)
    has_digit = any(c.isdigit() for c in p)
    specials = set("!@#$%^&*()_+-=[]{}|;:',.<>/?`~\"\\")
    has_special = any(c in specials for c in p)
    # Disallow unexpected control chars
    if any((not c.isalnum()) and c not in specials for c in p):
        return False
    return has_upper and has_lower and has_digit and has_special

def _derive(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _SALT, 210000, dklen=32)

def _ensure_expected():
    global _expected_hash, _expected_user
    if _expected_hash is not None and _expected_user is not None:
        return
    admin_user = os.environ.get("ADMIN_USER")
    if not admin_user:
        admin_user = "admin"
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_password is None or not _valid_password_policy(admin_password):
        _expected_hash = None
        _expected_user = None
        return
    _expected_hash = _derive(admin_password)
    _expected_user = admin_user

def do_login(username: str, password: str) -> str:
    if username is None or password is None:
        return "INVALID_INPUT"
    if not _valid_username(username) or not _valid_password_policy(password):
        return "INVALID_INPUT"
    _ensure_expected()
    if _expected_hash is None or _expected_user is None:
        return "SERVER_NOT_CONFIGURED"
    if username != _expected_user:
        return "ACCESS_DENIED"
    input_hash = _derive(password)
    return "REDIRECT:/admin_page" if hmac.compare_digest(input_hash, _expected_hash) else "ACCESS_DENIED"

if __name__ == "__main__":
    # Configure environment for testing
    os.environ["ADMIN_USER"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "StrongPassw0rd!X"

    print("TEST1 login():")
    print(login())

    print("\nTEST2 do_login(admin, correct):")
    print(do_login("admin", "StrongPassw0rd!X"))

    print("\nTEST3 do_login(admin, wrong password):")
    print(do_login("admin", "WrongPass123!"))

    print("\nTEST4 do_login(notadmin, correct password):")
    print(do_login("notadmin", "StrongPassw0rd!X"))

    print("\nTEST5 do_login(invalid user, short password):")
    print(do_login("bad user", "shortPwd!"))