import os
import re
import hashlib
import secrets

DB_FILE = "users_py.db"
SALT_LEN = 16
HASH_ITERATIONS = 100000
MAX_NAME_LEN = 100

def register_user(name: str, email: str, password: str) -> str:
    try:
        v = _validate_inputs(name, email, password)
        if v is not None:
            return v
        norm_email = email.strip().lower()

        if _email_exists(norm_email):
            return "Error: Email already registered."

        salt = secrets.token_bytes(SALT_LEN)
        # Use PBKDF2 with SHA-256
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
        record = f"{_escape_field(name.strip())}|{_escape_field(norm_email)}|{salt.hex()}|{hash_bytes.hex()}\n"
        with open(DB_FILE, "a", encoding="utf-8") as f:
            f.write(record)
        return "Success: User registered."
    except Exception as e:
        return f"Error: {str(e)}"

def _validate_inputs(name: str, email: str, password: str):
    if name is None or email is None or password is None:
        return "Error: Null input."
    name = name.strip()
    if len(name) == 0 or len(name) > MAX_NAME_LEN:
        return "Error: Invalid name length."
    if not re.match(r"^[A-Za-z][A-Za-z '\-]{0,99}$", name):
        return "Error: Name contains invalid characters."
    email = email.strip()
    if len(email) > 254 or not re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email):
        return "Error: Invalid email format."
    if '|' in name or '|' in email or '\n' in name or '\n' in email:
        return "Error: Invalid characters in input."
    # Password policy
    if len(password) < 8:
        return "Error: Password too short."
    lo = any(c.islower() for c in password)
    up = any(c.isupper() for c in password)
    di = any(c.isdigit() for c in password)
    sp = any(not c.isalnum() for c in password)
    if not (lo and up and di and sp):
        return "Error: Password must include upper, lower, digit, and special."
    return None

def _email_exists(email: str) -> bool:
    if not os.path.exists(DB_FILE):
        return False
    with open(DB_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("|")
            if len(parts) >= 2 and parts[1].lower() == email.lower():
                return True
    return False

def _escape_field(s: str) -> str:
    return s.replace("\n", "").replace("\r", "")

if __name__ == "__main__":
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    test_cases = [
        ("Alice Johnson", "alice@example.com", "Str0ng!Pass"),
        ("Bob O'Neil", "bob.oneil@example.org", "An0ther$Good"),
        ("Invalid|Name", "bademail@@example.com", "weakpass"),
        ("Charly", "alice@example.com", "Str0ng!Pass"),
        ("Dana Smith", "dana.smith@example.co", "Y3t@NotherGood"),
    ]

    for i, (n, e, p) in enumerate(test_cases, 1):
        print(f"Test {i}: {register_user(n, e, p)}")