import secrets
import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# ===================== Core 2FA Implementation =====================

SALT_LEN = 16
HASH_LEN = 32
PBKDF2_ITER = 210_000
OTP_TTL_SECONDS = 300  # 5 minutes

@dataclass
class User:
    username: str
    password_salt: bytes
    password_hash: bytes
    iterations: int
    otp_salt: Optional[bytes] = None
    otp_hash: Optional[bytes] = None
    otp_expiry: int = 0

USERS: Dict[str, User] = {}

def _is_valid_username(username: str) -> bool:
    if not (3 <= len(username) <= 64):
        return False
    for c in username:
        if not (c.isalnum() or c in "._-"):
            return False
    return True

def _is_strong_password(pwd: str) -> bool:
    if not (12 <= len(pwd) <= 1024):
        return False
    has_u = any('A' <= c <= 'Z' for c in pwd)
    has_l = any('a' <= c <= 'z' for c in pwd)
    has_d = any('0' <= c <= '9' for c in pwd)
    has_s = any(not c.isalnum() for c in pwd)
    return has_u and has_l and has_d and has_s

def _pbkdf2(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=length)

def _constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def _generate_numeric_otp(digits: int = 6) -> str:
    if digits <= 0 or digits > 9:
        digits = 6
    bound = 10 ** digits
    limit = (1 << 32) // bound * bound
    while True:
        val = secrets.randbits(32)
        if val < limit:
            num = val % bound
            break
    return f"{num:0{digits}d}"

def register_user(username: str, password: str) -> bool:
    if username is None or password is None:
        return False
    if not _is_valid_username(username):
        return False
    if not _is_strong_password(password):
        return False
    if username in USERS:
        return False
    salt = secrets.token_bytes(SALT_LEN)
    ph = _pbkdf2(password, salt, PBKDF2_ITER, HASH_LEN)
    USERS[username] = User(username=username, password_salt=salt, password_hash=ph, iterations=PBKDF2_ITER)
    return True

@dataclass
class LoginResult:
    success: bool
    otp: Optional[str]

def start_login(username: str, password: str) -> LoginResult:
    u = USERS.get(username)
    if u is None:
        return LoginResult(False, None)
    cand = _pbkdf2(password, u.password_salt, u.iterations, HASH_LEN)
    if not _constant_time_eq(cand, u.password_hash):
        return LoginResult(False, None)
    otp = _generate_numeric_otp(6)
    otp_salt = secrets.token_bytes(SALT_LEN)
    otp_hash = _pbkdf2(otp, otp_salt, PBKDF2_ITER, HASH_LEN)
    u.otp_salt = otp_salt
    u.otp_hash = otp_hash
    u.otp_expiry = int(time.time()) + OTP_TTL_SECONDS
    return LoginResult(True, otp)

def verify_otp(username: str, otp: str) -> bool:
    u = USERS.get(username)
    if u is None or u.otp_hash is None or u.otp_salt is None:
        return False
    if int(time.time()) > u.otp_expiry:
        return False
    cand = _pbkdf2(otp, u.otp_salt, PBKDF2_ITER, HASH_LEN)
    ok = _constant_time_eq(cand, u.otp_hash)
    if ok:
        u.otp_hash = None
        u.otp_salt = None
        u.otp_expiry = 0
    return ok

# Testing helper (not for production)
def expire_otp_for_test(username: str) -> None:
    u = USERS.get(username)
    if u:
        u.otp_expiry = int(time.time()) - 1

# ===================== Demo Tests =====================

def main() -> None:
    # Test 1: Successful registration and 2FA login
    reg1 = register_user("alice", "Str0ng!Passw0rd")
    lr1 = start_login("alice", "Str0ng!Passw0rd")
    v1 = lr1.success and verify_otp("alice", lr1.otp or "")
    print(f"Test1 (success 2FA): {reg1 and v1}")

    # Test 2: Wrong password
    lr2 = start_login("alice", "wrongPassword1!")
    print(f"Test2 (wrong password): {not lr2.success}")

    # Test 3: Wrong OTP
    lr3 = start_login("alice", "Str0ng!Passw0rd")
    v3 = lr3.success and verify_otp("alice", "000000")
    print(f"Test3 (wrong OTP): {not v3}")

    # Test 4: Expired OTP
    lr4 = start_login("alice", "Str0ng!Passw0rd")
    expire_otp_for_test("alice")
    v4 = lr4.success and verify_otp("alice", lr4.otp or "")
    print(f"Test4 (expired OTP): {not v4}")

    # Test 5: Another user end-to-end
    reg2 = register_user("bob_user", "An0ther$trongPass")
    lr5 = start_login("bob_user", "An0ther$trongPass")
    v5 = lr5.success and verify_otp("bob_user", lr5.otp or "")
    print(f"Test5 (second user success): {reg2 and v5}")

if __name__ == "__main__":
    main()