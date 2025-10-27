# Chain-of-Through step 1: Problem understanding
# Build a simple registration function that takes username/password and returns hashed password with salt.
# Chain-of-Through step 2: Security requirements
# - Use PBKDF2-HMAC-SHA256 with strong iterations and random salt.
# - Validate username and password strength.
# Chain-of-Through step 3: Secure coding generation (below)
# Chain-of-Through step 4: Code review (checks, exceptions)
# Chain-of-Through step 5: Secure code output

import base64
import hashlib
import json
import re
import secrets
from typing import Dict

_USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
_ITERATIONS = 200_000
_SALT_LEN = 16
_DK_LEN = 32

def _is_strong_password(password: str) -> bool:
    if password is None or len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special

def register_user(username: str, password: str) -> Dict[str, object]:
    if username is None or not _USERNAME_RE.match(username):
        raise ValueError("Invalid username. Use 3-32 chars: letters, digits, _ . -")
    if not _is_strong_password(password):
        raise ValueError("Weak password. Min 12 chars with upper, lower, digit, special.")
    salt = secrets.token_bytes(_SALT_LEN)
    # Note: Python strings are immutable; can't reliably wipe from memory.
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, _ITERATIONS, dklen=_DK_LEN)
    return {
        "username": username,
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": _ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode('ascii'),
        "hash_b64": base64.b64encode(dk).decode('ascii'),
    }

if __name__ == "__main__":
    tests = [
        ("alice_1", "StrongPassw0rd!"),
        ("Bob-User", "Another$tr0ngPass!"),
        ("charlie.user", "Y3tAn0ther#Pass!"),
        ("dave_2025", "S0methingComp!ex"),
        ("eve.test", "Unbr3akable@Key!")
    ]
    for u, p in tests:
        try:
            print(json.dumps(register_user(u, p)))
        except Exception as e:
            print(json.dumps({"error": str(e)}))