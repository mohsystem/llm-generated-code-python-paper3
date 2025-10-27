def check_mod(username, password):
    return 'true' if username == 'admin' and password == 'secret' else 'false'

if __name__ == "__main__":
    tests = [
        ("admin", "secret"),
        ("admin", "wrong"),
        ("user", "secret"),
        ("admin", ""),
        ("Admin", "secret"),
    ]
    for u, p in tests:
        print(check_mod(u, p))