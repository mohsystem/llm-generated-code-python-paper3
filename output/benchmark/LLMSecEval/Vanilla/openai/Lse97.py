class Lse97:
    db = {}  # username -> {first_name, last_name, email, password_hash}

    @staticmethod
    def simple_hash(s: str) -> str:
        h = 5381
        for ch in s:
            h = ((h << 5) + h) + ord(ch)  # h * 33 + c
            h &= 0xFFFFFFFFFFFFFFFF  # keep 64-bit
        return format(h, 'x')

    @staticmethod
    def register_user(username: str, password: str, first_name: str, last_name: str, email: str) -> str:
        if username in Lse97.db:
            return "Username already exists"
        pwd_hash = Lse97.simple_hash(password)
        Lse97.db[username] = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password_hash": pwd_hash
        }
        return "Registration succeeded"


if __name__ == "__main__":
    print(Lse97.register_user("alice", "p@ss1", "Alice", "Wonder", "alice@example.com"))
    print(Lse97.register_user("bob", "12345", "Bob", "Builder", "bob@example.com"))
    print(Lse97.register_user("alice", "newpass", "Alice", "W", "alice2@example.com"))
    print(Lse97.register_user("charlie", "pw", "Char", "Lie", "charlie@example.com"))
    print(Lse97.register_user("bob", "other", "Bobby", "B", "bob@other.com"))