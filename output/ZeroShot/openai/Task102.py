import os
import re
import hashlib
import hmac

DATABASE = {}
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,64}$')
ITERATIONS = 210000
SALT_LEN = 16
KEY_LEN = 32  # 256-bit

def _to_hex(b: bytes) -> str:
    return b.hex()

def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)

def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and USERNAME_RE.fullmatch(username) is not None

def is_valid_password(password: str) -> bool:
    if not isinstance(password, str) or len(password) < 8:
        return False
    lower = any(c.islower() for c in password)
    upper = any(c.isupper() for c in password)
    digit = any(c.isdigit() for c in password)
    special = any(not c.isalnum() for c in password)
    return (lower + upper + digit + special) >= 3

def hash_password(password: str) -> str:
    salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_LEN)
    return f"pbkdf2_sha256:{ITERATIONS}:{_to_hex(salt)}:{_to_hex(dk)}"

def verify_password_hash(stored: str, password: str) -> bool:
    try:
        alg, iters, salt_hex, hash_hex = stored.split(':', 3)
        if alg.lower() != 'pbkdf2_sha256':
            return False
        iters = int(iters)
        salt = _from_hex(salt_hex)
        expected = _from_hex(hash_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(expected))
        return hmac.compare_digest(expected, dk)
    except Exception:
        return False

def update_user_password(username: str, new_password: str) -> bool:
    if not is_valid_username(username) or not is_valid_password(new_password):
        return False
    DATABASE[username] = hash_password(new_password)
    return True

def get_stored_hash(username: str):
    return DATABASE.get(username)

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("alice", "CorrectHorseBatteryStaple!"),
        ("bob_123", "s3cureP@ssw0rd"),
        ("charlie", "anotherStrong#Pass1"),
        ("invalid user", "weak pass"),
        ("dave", "short7!")
    ]
    for u, p in tests:
        print("Update", u, "->", update_user_password(u, p))
    print("Stored alice:", get_stored_hash("alice") is not None)
    print("Verify alice correct:", verify_password_hash(get_stored_hash("alice"), "CorrectHorseBatteryStaple!"))
    print("Verify alice wrong:", verify_password_hash(get_stored_hash("alice"), "WrongPassword!"))
    print("Stored invalid user:", get_stored_hash("invalid user") is not None)