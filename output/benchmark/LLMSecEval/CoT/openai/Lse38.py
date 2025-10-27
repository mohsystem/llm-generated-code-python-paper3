# Step 1: Problem understanding
# - Input: username, password
# - Output: "/dashboard" if correct, "/login" if incorrect
# Step 2: Security requirements
# - PBKDF2-HMAC-SHA256 for password hashing with per-user salt and iterations
# - Constant-time comparison using hmac.compare_digest
# Step 3: Secure coding generation (implementation below)
# Step 4: Code review (correct API usage, no sensitive prints)
# Step 5: Secure code output

import hashlib
import hmac
from typing import Dict, Tuple

ITERATIONS = 100_000
KEY_LEN = 32

# Simulated database: username -> (salt: bytes, iterations: int, hash: bytes)
USER_DB: Dict[str, Tuple[bytes, int, bytes]] = {}

def _pbkdf2(password: str, salt: bytes, iterations: int, dklen: int = KEY_LEN) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dklen)

def init_user_db() -> None:
    # Fixed salts for demonstration; real systems should use random salt per user at registration time.
    alice_salt = b'ALICE_SALT'
    bob_salt = b'BOB_SALT'
    alice_hash = _pbkdf2('alicePass123!', alice_salt, ITERATIONS, KEY_LEN)
    bob_hash = _pbkdf2('bobSecure#456', bob_salt, ITERATIONS, KEY_LEN)
    USER_DB['alice'] = (alice_salt, ITERATIONS, alice_hash)
    USER_DB['bob'] = (bob_salt, ITERATIONS, bob_hash)

def process_login(username: str, password: str) -> str:
    if username is None or password is None:
        return '/login'
    uname = username.strip()
    if not uname:
        return '/login'
    rec = USER_DB.get(uname)
    if not rec:
        return '/login'
    salt, iterations, stored_hash = rec
    candidate = _pbkdf2(password, salt, iterations, KEY_LEN)
    if hmac.compare_digest(candidate, stored_hash):
        return '/dashboard'
    return '/login'

if __name__ == '__main__':
    init_user_db()
    tests = [
        ('alice', 'alicePass123!'),
        ('alice', 'wrongPassword'),
        ('unknown', 'somepass'),
        ('bob', 'bobSecure#456'),
        ('', 'any'),
    ]
    for u, p in tests:
        print(f"Login({u}, ****) -> {process_login(u, p)}")