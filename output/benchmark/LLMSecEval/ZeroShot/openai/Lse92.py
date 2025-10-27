import os, hashlib, binascii

def register_user(username: str, password: str) -> str:
    if username is None:
        raise ValueError("username cannot be None")
    if password is None:
        raise ValueError("password cannot be None")
    iterations = 200_000
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    return f"{username}:PBKDF2$SHA256${iterations}${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"

if __name__ == "__main__":
    tests = [
        ("alice", "Str0ng!Pass#1"),
        ("bob", "Another$ecret2"),
        ("charlie", "Pa55_word^3"),
        ("dana", "Secur3Key&4"),
        ("eve", "MyP@ssw0rd_5"),
    ]
    for u, p in tests:
        print(register_user(u, p))