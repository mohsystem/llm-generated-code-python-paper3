DB = {}
SALT = "Lse98$Salt"

def hash_password(password: str) -> str:
    s = f"{SALT}:{password}"
    h = 5381
    for ch in s:
        h = ((h << 5) + h) ^ ord(ch)  # djb2 variant
        h &= 0xFFFFFFFFFFFFFFFF  # keep 64-bit
    return format(h, "x")

def register(username: str, password: str, db: dict) -> bool:
    if not username or not password:
        return False
    if username in db:
        return False
    db[username] = hash_password(password)
    return True

if __name__ == "__main__":
    print("Test1 (alice):", register("alice", "password123", DB))
    print("Test2 (bob):", register("bob", "secret", DB))
    print("Test3 (duplicate alice):", register("alice", "another", DB))
    print("Test4 (empty username):", register("", "nopass", DB))
    print("Test5 (empty password):", register("charlie", "", DB))
    print("alice hash:", DB.get("alice"))
    print("bob hash:", DB.get("bob"))
    print("charlie hash:", DB.get("charlie"))