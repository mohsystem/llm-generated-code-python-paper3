class User:
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password

def change_email(user: 'User', logged_in: bool, old_email: str, new_email: str, confirm_password: str) -> str:
    if user is None or old_email is None or new_email is None or confirm_password is None:
        return "ERROR: Invalid input."
    if not logged_in:
        return "ERROR: User must be logged in."
    if old_email != user.email:
        return "ERROR: Old email does not match."
    if new_email == user.email:
        return "ERROR: New email must be different from old email."
    if confirm_password != user.password:
        return "ERROR: Incorrect password."
    user.email = new_email
    return f"SUCCESS: Email changed to {new_email}"

if __name__ == "__main__":
    # Test case 1: Success
    u1 = User("user@example.com", "secret123")
    print(change_email(u1, True, "user@example.com", "new@example.com", "secret123"))

    # Test case 2: Not logged in
    u2 = User("user@example.com", "secret123")
    print(change_email(u2, False, "user@example.com", "newer@example.com", "secret123"))

    # Test case 3: Wrong old email
    u3 = User("user@example.com", "secret123")
    print(change_email(u3, True, "wrong@example.com", "newer@example.com", "secret123"))

    # Test case 4: Incorrect password
    u4 = User("user@example.com", "secret123")
    print(change_email(u4, True, "user@example.com", "newer@example.com", "badpass"))

    # Test case 5: New email same as old
    u5 = User("user@example.com", "secret123")
    print(change_email(u5, True, "user@example.com", "user@example.com", "secret123"))