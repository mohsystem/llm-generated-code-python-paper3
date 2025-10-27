import os
import hashlib
import hmac

SALT_LEN = 16
ITERATIONS = 210000
KEY_LEN = 32  # 256-bit
DB = {}

def generate_salt(length: int) -> bytes:
    return os.urandom(length)

def hash_password(password: str, salt: bytes, iterations: int = ITERATIONS, key_len: int = KEY_LEN) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Password must be str")
    pw_bytes = password.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', pw_bytes, salt, iterations, dklen=key_len)

def to_hex(b: bytes) -> str:
    return b.hex()

def from_hex(h: str) -> bytes:
    return bytes.fromhex(h)

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def register(username: str, password: str) -> str:
    if not username or not isinstance(username, str):
        raise ValueError("Username required")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    salt = generate_salt(SALT_LEN)
    hashed = hash_password(password, salt)
    record = to_hex(salt) + to_hex(hashed)
    DB[username] = record
    return record

def verify(username: str, password: str) -> bool:
    record = DB.get(username)
    if not record:
        return False
    salt_hex = record[:SALT_LEN*2]
    hash_hex = record[SALT_LEN*2:]
    salt = from_hex(salt_hex)
    expected = from_hex(hash_hex)
    actual = hash_password(password, salt)
    return constant_time_equals(expected, actual)

def get_stored_record(username: str) -> str:
    return DB.get(username, "")

if __name__ == "__main__":
    # 5 test cases
    users = ["alice", "bob", "charlie", "dave", "eve"]
    passwords = ["password1!", "S33cr3t!", "superlongpassword123", "Pa$$w0rd123", "Secure🔒123!"]
    for u, p in zip(users, passwords):
        stored = register(u, p)
        print(f"{u} -> {stored}")

    print("Verify alice correct:", verify("alice", "password1!"))
    print("Verify alice wrong:", verify("alice", "wrongpass"))
    print("Verify bob correct:", verify("bob", "S33cr3t!"))
    print("Stored for charlie:", get_stored_record("charlie"))
    print("Verify eve correct:", verify("eve", "Secure🔒123!"))