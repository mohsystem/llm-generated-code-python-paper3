def check_mod(username, password):
    if username is None or password is None:
        return "false"
    return "true" if (username == "admin" and password == "secret") else "false"


if __name__ == "__main__":
    tests = [
        ("admin", "secret"),
        ("Admin", "secret"),
        ("admin", "Secret"),
        ("user", "secret"),
        ("admin", "secret123"),
    ]
    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {check_mod(u, p)}")