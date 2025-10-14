def authenticate(users: dict, username: str, password: str) -> bool:
    if users is None or username is None or password is None:
        return False
    return users.get(username) == password


if __name__ == "__main__":
    users = {
        "alice": "pass123",
        "bob": "qwerty",
        "charlie": "letmein",
    }

    print("Test 1 (alice, correct):", authenticate(users, "alice", "pass123"))
    print("Test 2 (bob, wrong):", authenticate(users, "bob", "wrong"))
    print("Test 3 (unknown user):", authenticate(users, "eve", "anything"))
    print("Test 4 (charlie, empty password):", authenticate(users, "charlie", ""))
    print("Test 5 (case sensitivity):", authenticate(users, "Alice", "pass123"))