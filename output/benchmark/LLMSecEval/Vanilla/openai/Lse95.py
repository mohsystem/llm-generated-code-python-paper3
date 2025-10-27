import secrets
import hmac

SALT_LEN = 16
DB = {}  # simple in-memory "database": username -> "hash:salt"

def generate_salt(n: int) -> bytes:
    return secrets.token_bytes(n)

def fnv1a64_hex(password: str, salt: bytes) -> str:
    fnv_offset = 0xcbf29ce484222325
    fnv_prime = 0x100000001b3
    h = fnv_offset
    data = password.encode('utf-8') + salt
    for b in data:
        h ^= b
        h = (h * fnv_prime) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""

def register_user(username: str, password: str) -> bool:
    if username is None or password is None:
        return False
    if username in DB:
        return False
    salt = generate_salt(SALT_LEN)
    hash_hex = fnv1a64_hex(password, salt)
    DB[username] = f"{hash_hex}:{bytes_to_hex(salt)}"
    return True

def login_user(username: str, password: str) -> bool:
    rec = DB.get(username)
    if not rec or ':' not in rec:
        return False
    stored_hash, salt_hex = rec.split(':', 1)
    salt = hex_to_bytes(salt_hex)
    calc = fnv1a64_hex(password, salt)
    return hmac.compare_digest(stored_hash, calc)

if __name__ == "__main__":
    # 5 test cases
    print("Register alice/password123:", register_user("alice", "password123"))  # True
    print("Login alice/password123:", login_user("alice", "password123"))        # True
    print("Login alice/wrong:", login_user("alice", "wrong"))                    # False
    print("Register alice/another:", register_user("alice", "another"))          # False
    print("Register bob/S3cret!:", register_user("bob", "S3cret!"))              # True