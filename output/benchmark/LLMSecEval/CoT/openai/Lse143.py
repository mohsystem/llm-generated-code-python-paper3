class Lse143:
    database = set()
    mailing_list = set()

    @classmethod
    def initialize_db(cls):
        cls.database = {"alice@example.com", "bob@example.com", "dana@example.com"}
        cls.mailing_list = set(cls.database)

    @classmethod
    def unsubscribe(cls, email: str) -> str:
        if not email:
            return "Invalid email"
        if email in cls.database:
            cls.database.remove(email)
            cls.mailing_list.discard(email)
            return f"Unsubscribed: {email}"
        else:
            return f"User not subscribed: {email}"

if __name__ == "__main__":
    Lse143.initialize_db()
    tests = [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "bob@example.com",
        "dana@example.com",
    ]
    for t in tests:
        print(Lse143.unsubscribe(t))