# In-memory "database"
database = []

def hash_password(password: str) -> str:
    # FNV-1a 64-bit
    hash_val = 0xcbf29ce484222325
    prime = 0x100000001b3
    for b in password.encode("utf-8"):
        hash_val ^= b
        hash_val = (hash_val * prime) & 0xFFFFFFFFFFFFFFFF
    return f"{hash_val:016x}"

def insert_user(username: str, password: str, db: list) -> bool:
    hashed = hash_password(password)
    db.append({"username": username, "hashed_password": hashed})
    return True

def main():
    insert_user("alice", "password123", database)
    insert_user("bob", "s3cr3t", database)
    insert_user("charlie", "letmein", database)
    insert_user("diana", "P@ssw0rd!", database)
    insert_user("eve", "qwerty", database)

    print("Current database:")
    for i, rec in enumerate(database, 1):
        print(f"{i}) {rec['username']} | {rec['hashed_password']}")

if __name__ == "__main__":
    main()