class Auth:
    def __init__(self):
        self.users = {}
        self.current_email = None

    def add_user(self, email: str, password: str) -> bool:
        if email is None or password is None:
            return False
        if email in self.users:
            return False
        self.users[email] = password
        return True

    def login(self, email: str, password: str) -> bool:
        if email is None or password is None:
            return False
        if self.users.get(email) == password:
            self.current_email = email
            return True
        return False

    def logout(self):
        self.current_email = None

    def is_logged_in(self) -> bool:
        return self.current_email is not None

    def get_current_email(self):
        return self.current_email

    def change_email(self, old_email: str, new_email: str, confirm_password: str) -> bool:
        if not self.is_logged_in():
            return False
        if old_email is None or new_email is None or confirm_password is None:
            return False
        if old_email not in self.users:
            return False
        if old_email != self.current_email:
            return False
        if self.users[old_email] != confirm_password:
            return False
        if new_email in self.users:
            return False
        self.users[new_email] = self.users.pop(old_email)
        self.current_email = new_email
        return True


def seed():
    a = Auth()
    a.add_user("alice@example.com", "alice123")
    a.add_user("bob@example.com", "bobpwd")
    a.add_user("charlie@example.com", "charlie!")
    return a


if __name__ == "__main__":
    # Test 1: Successful login and change
    t1 = seed()
    t1_login = t1.login("alice@example.com", "alice123")
    t1_change = t1.change_email("alice@example.com", "alice.new@example.com", "alice123")
    print("Test1 login=", t1_login, " change=", t1_change, " current=", t1.get_current_email())

    # Test 2: Attempt change without login
    t2 = seed()
    t2_change = t2.change_email("bob@example.com", "bob.new@example.com", "bobpwd")
    print("Test2 changeWithoutLogin=", t2_change)

    # Test 3: Wrong confirm password
    t3 = seed()
    t3_login = t3.login("bob@example.com", "bobpwd")
    t3_change = t3.change_email("bob@example.com", "bob.new@example.com", "wrong")
    print("Test3 login=", t3_login, " changeWithWrongPassword=", t3_change)

    # Test 4: Non-existing old email while logged in
    t4 = seed()
    t4_login = t4.login("charlie@example.com", "charlie!")
    t4_change = t4.change_email("ghost@example.com", "ghost2@example.com", "charlie!")
    print("Test4 login=", t4_login, " changeWithNonExistingOldEmail=", t4_change)

    # Test 5: New email already in use
    t5 = seed()
    t5_login = t5.login("alice@example.com", "alice123")
    t5_change = t5.change_email("alice@example.com", "bob@example.com", "alice123")
    print("Test5 login=", t5_login, " changeToExistingEmail=", t5_change)