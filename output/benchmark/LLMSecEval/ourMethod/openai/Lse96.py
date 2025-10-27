import base64
import hashlib
import hmac
import re
import secrets
from typing import Dict, Optional

# In-memory "database": username -> base64(salt||hash)
DATABASE: Dict[str, str] = {}

SALT_LEN = 16  # 128-bit
DERIVED_KEY_LEN = 32  # 256-bit
PBKDF2_ITERATIONS = 210_000

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return USERNAME_RE.fullmatch(username) is not None

def is_strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 12:
        return False
    if any(ch.isspace() for ch in password):
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special

def generate_salt(length: int = SALT_LEN) -> bytes:
    if length < 16 or length > 64:
        raise ValueError("Invalid salt length")
    return secrets.token_bytes(length)

def hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS, dk_len: int = DERIVED_KEY_LEN) -> bytes:
    if not isinstance(password, str) or not isinstance(salt, (bytes, bytearray)):
        raise ValueError("Invalid inputs")
    if iterations < 210_000:
        raise ValueError("Iterations too low")
    if dk_len < 16 or dk_len > 64:
        raise ValueError("Invalid dk length")
    # Use bytearray for transient buffer and wipe it after
    pbuf = bytearray(password.encode("utf-8"))
    try:
        dk = hashlib.pbkdf2_hmac("sha256", pbuf, salt, iterations, dklen=dk_len)
        return dk
    finally:
        for i in range(len(pbuf)):
            pbuf[i] = 0

def concat_salt_hash_b64(salt: bytes, h: bytes) -> str:
    combined = salt + h
    encoded = base64.b64encode(combined).decode("ascii")
    return encoded

def register_user(username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_strong_password(password):
        return False
    if username in DATABASE:
        return False
    salt = generate_salt(SALT_LEN)
    h = hash_password(password, salt, PBKDF2_ITERATIONS, DERIVED_KEY_LEN)
    record = concat_salt_hash_b64(salt, h)
    DATABASE[username] = record
    return True

def verify_user(username: str, password: str) -> bool:
    record = DATABASE.get(username)
    if not record:
        return False
    combined = base64.b64decode(record.encode("ascii"))
    if len(combined) != SALT_LEN + DERIVED_KEY_LEN:
        return False
    salt = combined[:SALT_LEN]
    stored_hash = combined[SALT_LEN:]
    candidate = hash_password(password, salt, PBKDF2_ITERATIONS, DERIVED_KEY_LEN)
    return hmac.compare_digest(stored_hash, candidate)

def main() -> None:
    # Test 1: valid registration
    t1 = register_user("alice", "Str0ng!Passw0rd")
    print(f"Test1 register valid: {t1}")

    # Test 2: invalid username
    t2 = register_user("a", "Another$trong123")
    print(f"Test2 invalid username rejected: {not t2}")

    # Test 3: weak password
    t3 = register_user("bob", "weakpass")
    print(f"Test3 weak password rejected: {not t3}")

    # Test 4: duplicate username
    t4a = register_user("carol", "V3ry$trongPass!")
    t4b = register_user("carol", "Diff3rent$trong!")
    print(f"Test4 duplicate username rejected: {t4a and (not t4b)}")

    # Test 5: same password yields different stored records due to unique salts
    r1 = register_user("dave", "SamePassw0rd!!")
    r2 = register_user("erin", "SamePassw0rd!!")
    same_stored = False
    if r1 and r2:
        same_stored = DATABASE.get("dave") == DATABASE.get("erin")
    v1 = verify_user("dave", "SamePassw0rd!!")
    v2 = verify_user("erin", "SamePassw0rd!!")
    print(f"Test5 unique salts and verify: {r1 and r2 and (not same_stored) and v1 and v2}")

if __name__ == "__main__":
    main()