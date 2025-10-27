import os
import hashlib
import hmac

ITERATIONS = 100_000
KEY_LEN = 32
SALT_LEN = 16

class InMemoryDB:
    def __init__(self):
        self.users = {}  # username -> (salt: bytes, hash: bytes)

def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=KEY_LEN)

def _safe_trim(s: str) -> str:
    return "" if s is None else s.strip()

def add_user(db: InMemoryDB, username: str, password: str) -> None:
    if username is None or password is None:
        return
    u = _safe_trim(username)
    if not u:
        return
    salt = os.urandom(SALT_LEN)
    h = _pbkdf2(password, salt)
    db.users[u] = (salt, h)

def login(db: InMemoryDB, username: str, password: str) -> str:
    u = _safe_trim(username)
    if not u or password is None:
        return "redirect:/login"
    rec = db.users.get(u)
    if rec is None:
        return "redirect:/login"
    salt, stored = rec
    cand = _pbkdf2(password, salt)
    ok = hmac.compare_digest(stored, cand)
    return "redirect:/dashboard" if ok else "redirect:/login"

if __name__ == "__main__":
    db = InMemoryDB()
    add_user(db, "alice", "CorrectHorseBatteryStaple!")
    add_user(db, "bob", "b0b$ecret")
    add_user(db, "eve", "n0t_used")

    # 5 test cases
    print("Test1 (alice correct):", login(db, "alice", "CorrectHorseBatteryStaple!"))  # dashboard
    print("Test2 (alice wrong pw):", login(db, "alice", "wrong"))  # login
    print("Test3 (unknown user):", login(db, "charlie", "anything"))  # login
    print("Test4 (empty username):", login(db, "   ", "whatever"))  # login
    print("Test5 (bob correct with trim):", login(db, "  bob ", "b0b$ecret"))  # dashboard