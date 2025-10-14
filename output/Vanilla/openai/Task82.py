import hashlib

def hash_password_with_salt(password: str, salt: str) -> str:
    m = hashlib.sha256()
    m.update((salt + password).encode("utf-8"))
    return m.hexdigest()

if __name__ == "__main__":
    tests = [
        ("password123", "NaCl"),
        ("hunter2", "S@1t!"),
        ("Tr0ub4dor&3", "pepper"),
        ("correcthorsebatterystaple", ""),
        ("", "onlysalt"),
    ]
    for pw, salt in tests:
        print(f'password="{pw}", salt="{salt}" -> {hash_password_with_salt(pw, salt)}')