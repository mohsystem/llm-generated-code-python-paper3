import re
import secrets
import hmac
import hashlib

# In-memory database: username -> hex(hash) + hex(salt)
DB = {}

SALT_LEN = 16  # bytes
KEY_LEN = 32   # bytes
ITERATIONS = 210_000

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return bool(USERNAME_RE.fullmatch(username))

def is_strong_password(password: str) -> bool:
    if not isinstance(password, str) or len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    specials = set("!@#$%^&*()-_=+[]{}|;:',.<>/?`~\"\\ ")
    has_special = any(c in specials for c in password)
    return has_upper and has_lower and has_digit and has_special

def register_user(username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_strong_password(password):
        return False
    if username in DB:
        return False
    salt = secrets.token_bytes(SALT_LEN)
    pwd_bytes = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, ITERATIONS, dklen=KEY_LEN)
    stored = dk.hex() + salt.hex()  # append salt to hash
    DB[username] = stored
    # Avoid keeping sensitive in memory longer than needed (best-effort)
    # Python doesn't offer guaranteed zeroization; reassign variables.
    pwd_bytes = b"\x00" * len(pwd_bytes)
    return True

def verify_login(username: str, password: str) -> bool:
    stored = DB.get(username)
    if not stored or len(stored) < SALT_LEN * 2:
        return False
    salt_hex = stored[-SALT_LEN * 2:]
    hash_hex = stored[:-SALT_LEN * 2]
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    pwd_bytes = password.encode("utf-8")
    computed = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, ITERATIONS, dklen=KEY_LEN)
    ok = hmac.compare_digest(expected, computed)
    # Best-effort cleanup
    pwd_bytes = b"\x00" * len(pwd_bytes)
    return ok

def main():
    # 1) Successful registration
    print("Test1 register alice:", register_user("alice_01", "Str0ng!Passw0rd"))
    # 2) Successful login
    print("Test2 login alice correct:", verify_login("alice_01", "Str0ng!Passw0rd"))
    # 3) Failed login due to wrong password
    print("Test3 login alice wrong:", verify_login("alice_01", "WrongPassword!1"))
    # 4) Duplicate registration should fail
    print("Test4 duplicate register alice:", register_user("alice_01", "An0ther!Passw0rd"))
    # 5) Weak password should fail registration
    print("Test5 register weak bob:", register_user("bob", "weakpass"))

if __name__ == "__main__":
    main()