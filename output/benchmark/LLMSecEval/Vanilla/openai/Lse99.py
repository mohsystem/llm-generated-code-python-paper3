import hashlib

class Lse99:
    _db = {}

    @staticmethod
    def hash_password(password: str) -> str:
        if password is None:
            password = ""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def insert_user(username: str, password: str) -> bool:
        if username is None or password is None:
            return False
        if username in Lse99._db:
            return False
        Lse99._db[username] = Lse99.hash_password(password)
        return True

    @staticmethod
    def get_hashed_password(username: str):
        return Lse99._db.get(username)

def main():
    tests = [
        ("alice", "password123"),
        ("bob", "s3cr3t!"),
        ("charlie", "Pa$$w0rd"),
        ("alice", "newpass"),
        ("eve", ""),
    ]
    for u, p in tests:
        ok = Lse99.insert_user(u, p)
        print(f"Insert({u}): {ok} | hash={Lse99.get_hashed_password(u)}")
    print(f"Total users: {len(Lse99._db)}")

if __name__ == "__main__":
    main()