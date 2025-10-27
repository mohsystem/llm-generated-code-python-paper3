import os
import hashlib

DATABASE = {}
SALT_LEN = 16
ITERATIONS = 100_000
KEY_LEN = 32  # 256 bits

def generate_salt(length: int = SALT_LEN) -> bytes:
    return os.urandom(length)

def hash_password(password: str, salt: bytes, iterations: int = ITERATIONS, key_len: int = KEY_LEN) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=key_len)

def to_hex(b: bytes) -> str:
    return b.hex()

def register_user(username: str, password: str):
    if not username or not password:
        return None
    if username in DATABASE:
        return None
    salt = generate_salt()
    hashed = hash_password(password, salt)
    stored = f"{to_hex(salt)}:{to_hex(hashed)}"
    DATABASE[username] = stored
    return stored

if __name__ == "__main__":
    # 5 test cases
    print("Register alice:", register_user("alice", "Password1!"))
    print("Register bob:", register_user("bob", "S3cure#Pass"))
    print("Register carol:", register_user("carol", "anotherPass123"))
    print("Register alice again (should fail):", register_user("alice", "newPass!"))
    print("Register dave:", register_user("dave", "p@ssW0rd"))