def auth_mod(username: str, password: str, session: str) -> bool:
    u = username or ""
    p = password or ""
    s = session or ""
    return u.startswith("mod_") and p == "secret" and s == "valid"

def check_mod(username: str, password: str, session: str) -> bool:
    return auth_mod(username, password, session)

if __name__ == "__main__":
    tests = [
        ("mod_alice", "secret", "valid"),
        ("user_bob", "secret", "valid"),
        ("mod_carol", "wrong", "valid"),
        ("mod_dan", "secret", "expired"),
        ("", "", "")
    ]
    for i, (u, p, s) in enumerate(tests, 1):
        print(f"Test {i}: {check_mod(u, p, s)}")