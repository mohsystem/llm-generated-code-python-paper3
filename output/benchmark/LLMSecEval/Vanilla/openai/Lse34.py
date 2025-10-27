def login_redirect(username: str, password: str, database: dict) -> str:
    stored = database.get(username)
    return "/dashboard" if stored is not None and stored == password else "/login"

def main():
    db = {
        "alice": "pass123",
        "bob": "secret",
        "carol": "hunter2",
    }

    tests = [
        ("alice", "pass123"),
        ("alice", "wrong"),
        ("unknown", "pass123"),
        ("bob", "secret"),
        ("carol", "HUNTER2"),
    ]

    for i, (u, p) in enumerate(tests, 1):
        result = login_redirect(u, p, db)
        print(f"Test {i} ({u}): {result}")

if __name__ == "__main__":
    main()