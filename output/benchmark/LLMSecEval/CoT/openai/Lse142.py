class Lse142:
    def __init__(self, initial_emails):
        self.database = set(initial_emails)

    def unsubscribe(self, email: str) -> str:
        if email in self.database:
            self.database.remove(email)
            return "Email removed from database."
        else:
            return "Email not found in database."


if __name__ == "__main__":
    service = Lse142([
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
    ])

    tests = [
        "alice@example.com",
        "dave@example.com",
        "bob@example.com",
        "alice@example.com",
        "carol@example.com",
    ]

    for email in tests:
        print(f"{email} -> {service.unsubscribe(email)}")