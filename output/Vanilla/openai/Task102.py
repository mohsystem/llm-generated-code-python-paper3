SALT = "Task102_SALT"

def fnv1a64_hex(s: str) -> str:
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

def hash_password(password: str) -> str:
    return fnv1a64_hex(SALT + password)

def update_password(db: dict, username: str, new_password: str) -> bool:
    if username not in db or not new_password:
        return False
    db[username] = hash_password(new_password)
    return True

def get_password_hash(db: dict, username: str):
    return db.get(username)

def init_db() -> dict:
    return {
        "alice": hash_password("old1"),
        "bob": hash_password("old2"),
        "charlie": hash_password("old3"),
    }

def main():
    db = init_db()
    print(f"Initial DB: {db}")

    r1 = update_password(db, "alice", "newPass1")
    print(f"Test1 update alice: {r1} hash={get_password_hash(db, 'alice')}")

    r2 = update_password(db, "bob", "P@ssw0rd!")
    print(f"Test2 update bob: {r2} hash={get_password_hash(db, 'bob')}")

    r3 = update_password(db, "david", "something")
    print(f"Test3 update david: {r3}")

    r4 = update_password(db, "charlie", "")
    print(f"Test4 update charlie with empty: {r4} hash={get_password_hash(db, 'charlie')}")

    r5 = update_password(db, "alice", "another123")
    print(f"Test5 update alice again: {r5} hash={get_password_hash(db, 'alice')}")

if __name__ == "__main__":
    main()