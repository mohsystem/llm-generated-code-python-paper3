class Lse39:
    @staticmethod
    def login(username: str, password: str) -> str:
        if username is None or password is None:
            return "Incorrect username or password"
        return (
            "Redirecting to session page"
            if (username == "admin" and password == "password123")
            else "Incorrect username or password"
        )

if __name__ == "__main__":
    tests = [
        ("admin", "password123"),
        ("admin", "wrong"),
        ("user", "password123"),
        ("", "password123"),
        ("Admin", "password123"),
    ]
    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {Lse39.login(u, p)}")