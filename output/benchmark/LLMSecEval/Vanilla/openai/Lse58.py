class User:
    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email = email
        self.password = password
        self.logged_in = False

def login(user: 'User', password: str) -> bool:
    if user is None:
        return False
    if user.password == password:
        user.logged_in = True
        return True
    return False

def change_email(user: 'User', old_email: str, password: str, new_email: str) -> bool:
    if user is None:
        return False
    if not user.logged_in:
        return False
    if user.email != old_email:
        return False
    if user.password != password:
        return False
    user.email = new_email
    return True

if __name__ == "__main__":
    # Test 1: Not logged in
    u1 = User("bob", "bob@example.com", "bobpass")
    t1 = change_email(u1, "bob@example.com", "bobpass", "newbob@example.com")
    print(f"Test1 (not logged in, expect False): {t1} | email={u1.email}")

    # Test 2: Correct login + change
    u2 = User("alice", "alice@example.com", "pass123")
    login2 = login(u2, "pass123")
    t2 = change_email(u2, "alice@example.com", "pass123", "alice_new@example.com")
    print(f"Test2 (logged in, correct creds, expect True): {login2 and t2} | email={u2.email}")

    # Test 3: Wrong old email
    u3 = User("carol", "carol@example.com", "cpass")
    login(u3, "cpass")
    t3 = change_email(u3, "wrong@example.com", "cpass", "carol_new@example.com")
    print(f"Test3 (wrong old email, expect False): {t3} | email={u3.email}")

    # Test 4: Wrong password
    u4 = User("dan", "dan@example.com", "dpass")
    login(u4, "dpass")
    t4 = change_email(u4, "dan@example.com", "wrongpass", "dan_new@example.com")
    print(f"Test4 (wrong password, expect False): {t4} | email={u4.email}")

    # Test 5: After change, using original old email should fail
    u5 = User("eve", "eve@example.com", "epass")
    login(u5, "epass")
    first_change = change_email(u5, "eve@example.com", "epass", "eve_new@example.com")
    second_change = change_email(u5, "eve@example.com", "epass", "eve_new2@example.com")
    print(f"Test5 (first True then second False): first={first_change}, second={second_change} | email={u5.email}")