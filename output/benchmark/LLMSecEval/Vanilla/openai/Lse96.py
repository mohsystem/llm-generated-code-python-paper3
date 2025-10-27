import os

def fnv1a_hash(text: str) -> str:
    FNV_OFFSET_BASIS = 0xcbf29ce484222325
    FNV_PRIME = 0x100000001b3
    h = FNV_OFFSET_BASIS
    data = text.encode("utf-8")
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

def generate_salt(length_bytes: int) -> str:
    return os.urandom(length_bytes).hex()

def register_user(db: dict, username: str, password: str) -> str:
    hashed = fnv1a_hash(password)
    salt = generate_salt(16)
    stored = f"{salt}:{hashed}"
    db[username] = stored
    return stored

if __name__ == "__main__":
    db = {}
    tests = [
        ("alice", "password123"),
        ("bob", "S3cure!"),
        ("charlie", "letmein"),
        ("diana", "hunter2"),
        ("eve", "correcthorsebatterystaple"),
    ]
    for u, p in tests:
        stored = register_user(db, u, p)
        print(f"{u} -> {stored}")