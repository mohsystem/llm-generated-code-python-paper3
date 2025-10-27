import os
import re
import secrets
import tempfile
import hashlib

ITERATIONS = 210_000
SALT_LEN = 16
DK_LEN = 32
MAX_USERS = 100_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

def _is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username))

def _check_password_policy(password: str):
    if len(password) < 12:
        return "Password must be at least 12 characters long"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if not (has_upper and has_lower and has_digit and has_special):
        return "Password must include upper, lower, digit, and special character"
    return None

def register_user(db_path: str, username: str, password: str) -> str:
    if not db_path:
        return "ERROR: Invalid database path"
    if username is None or password is None:
        return "ERROR: Null input"
    if not _is_valid_username(username):
        return "ERROR: Invalid username (3-32 chars; allowed A-Z, a-z, 0-9, _ . -)"
    policy = _check_password_policy(password)
    if policy:
        return f"ERROR: {policy}"

    existing = {}
    count = 0
    if os.path.exists(db_path):
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) != 4:
                        continue
                    existing[parts[0]] = line
                    count += 1
                    if count > MAX_USERS:
                        return "ERROR: Database too large"
        except OSError:
            return "ERROR: Unable to read database"
        if username in existing:
            return "ERROR: Username already exists"

    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=DK_LEN)

    record = f"{username}|{ITERATIONS}|{salt.hex()}|{dk.hex()}"
    out_lines = list(existing.values()) + [record]

    dir_name = os.path.dirname(db_path) or "."
    try:
        fd, tmp_name = tempfile.mkstemp(prefix="users_tmp_", suffix=".db", dir=dir_name, text=True)
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for l in out_lines:
                f.write(l + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, db_path)
    except OSError:
        try:
            if 'tmp_name' in locals():
                os.unlink(tmp_name)
        except Exception:
            pass
        return "ERROR: Unable to write database"

    return "OK"

def _run_tests():
    rnd = secrets.token_hex(8)
    db_path = os.path.join(tempfile.gettempdir(), f"users_py_{rnd}.db")
    tests = [
        ("alice", "Str0ngP@ssw0rd!"),
        ("bob", "weakpass"),
        ("invalid name", "Val1dP@ssw0rd!!"),
        ("alice", "An0ther$tr0ng!"),
        ("charlie", "An0th3r$tr0ng!")
    ]
    for i, (u, p) in enumerate(tests, 1):
        res = register_user(db_path, u, p)
        print(f"Test {i}: {res}")

if __name__ == "__main__":
    _run_tests()