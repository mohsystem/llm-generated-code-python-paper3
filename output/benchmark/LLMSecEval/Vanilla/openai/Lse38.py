# Returns "dashboard" if credentials are correct, otherwise "login"
def login(username, password, db=None):
    if db is None:
        db = {
            "alice": "password123",
            "bob": "qwerty",
            "charlie": "charlie!",
            "dana": "D@n@2025",
            "eve": "12345",
        }
    if username is None or password is None:
        return "login"
    return "dashboard" if db.get(username) == password else "login"

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("alice", "password123"),  # correct
        ("alice", "wrong"),        # wrong password
        ("unknown", "whatever"),   # unknown user
        ("Bob", "qwerty"),         # case sensitivity
        ("", ""),                  # empty credentials
    ]
    for u, p in tests:
        print(f'login("{u}", "{p}") => {login(u, p)}')