# Chain-of-Through process in code generation:
# 1) Problem understanding:
#    - Accept username and a new password, securely hash it, and update an in-memory "database".
# 2) Security requirements:
#    - Use PBKDF2-HMAC-SHA256 with random salt and high iterations.
#    - Enforce basic password policy, constant-time compare, minimal output.
# 3) Secure coding generation:
#    - Implement hashing, verification, input checks.
# 4) Code review:
#    - Confirm no secrets printed, strong iterations, constant-time compare, safe handling.
# 5) Secure code output:
#    - Final functions: hash_password, update_password, verify_password, with 5 test cases in main.

import os
import hmac
import hashlib

# Simulated in-memory "database"
class InMemoryDB:
    def __init__(self):
        self._store = {}

    def get(self, username: str):
        return self._store.get(username)

    def put(self, username: str, record: dict):
        self._store[username] = record

    def contains(self, username: str) -> bool:
        return username in self._store

DEFAULT_ITERATIONS = 200_000
SALT_LENGTH_BYTES = 16
KEY_LENGTH_BYTES = 32
ALGO = "PBKDF2-HMAC-SHA256"

def is_strong_password(pwd: str) -> bool:
    if pwd is None or len(pwd) < 10:
        return False
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    specials = set("!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~")
    has_special = any(c in specials for c in pwd)
    if not (has_upper and has_lower and has_digit and has_special):
        return False
    lower = pwd.lower()
    for banned in ["password", "qwerty", "12345", "abc123", "letmein", "admin", "welcome"]:
        if banned in lower:
            return False
    return True

def hash_password(password: str) -> dict:
    if not password:
        raise ValueError("Password must not be empty")
    salt = os.urandom(SALT_LENGTH_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, DEFAULT_ITERATIONS, KEY_LENGTH_BYTES)
    return {
        "algo": ALGO,
        "iterations": DEFAULT_ITERATIONS,
        "salt": salt,
        "hash": dk,
        "key_len": KEY_LENGTH_BYTES,
    }

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def update_password(db: InMemoryDB, username: str, new_password: str) -> bool:
    if db is None or not username:
        return False
    if not is_strong_password(new_password):
        return False
    rec = hash_password(new_password)
    db.put(username, rec)
    return True

def verify_password(db: InMemoryDB, username: str, attempt: str) -> bool:
    if db is None or not username or attempt is None:
        return False
    rec = db.get(username)
    if rec is None:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", attempt.encode("utf-8"), rec["salt"], rec["iterations"], rec["key_len"])
    return constant_time_equals(dk, rec["hash"])

if __name__ == "__main__":
    db = InMemoryDB()

    # Test 1: Create and then update Alice, verify old fails and new works
    t1_create = update_password(db, "alice", "Str0ng!Pass")
    t1_update = update_password(db, "alice", "EvenStr0nger@2025")
    t1_verify_old = verify_password(db, "alice", "Str0ng!Pass")
    t1_verify_new = verify_password(db, "alice", "EvenStr0nger@2025")
    print("Test1 created=", t1_create, "updated=", t1_update, "verifyOld=", t1_verify_old, "verifyNew=", t1_verify_new)

    # Test 2: Weak password rejection
    t2 = update_password(db, "bob", "123456")
    print("Test2 weakUpdate=", t2)

    # Test 3: Create Bob with strong password, update to same password (allowed), verify
    t3_create = update_password(db, "bob", "Bob$Pass1X")
    t3_update_same = update_password(db, "bob", "Bob$Pass1X")
    t3_verify = verify_password(db, "bob", "Bob$Pass1X")
    print("Test3 createdBob=", t3_create, "updateSameBob=", t3_update_same, "verifyBob=", t3_verify)

    # Test 4: Upsert Charlie
    t4_upsert = update_password(db, "charlie", "Good#Pass2025")
    t4_verify = verify_password(db, "charlie", "Good#Pass2025")
    print("Test4 upsertCharlie=", t4_upsert, "verifyCharlie=", t4_verify)

    # Test 5: Multiple updates for Dave and verify only last works
    d1 = update_password(db, "dave", "Alpha@2025X")
    d2 = update_password(db, "dave", "Beta#2026Y")
    d3 = update_password(db, "dave", "Gamma$2027Z")
    v_old1 = verify_password(db, "dave", "Alpha@2025X")
    v_old2 = verify_password(db, "dave", "Beta#2026Y")
    v_new = verify_password(db, "dave", "Gamma$2027Z")
    print("Test5 updates=", (d1 and d2 and d3), "verifyOld1=", v_old1, "verifyOld2=", v_old2, "verifyNew=", v_new)