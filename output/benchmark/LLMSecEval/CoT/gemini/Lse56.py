# In a real application, never store passwords in plain text.
# Always use a strong, salted hashing algorithm like Argon2, scrypt, or bcrypt.
class User:
    def __init__(self, email, password):
        self.email = email
        self.password = password  # Plain text for demonstration only.
        self.is_logged_in = False # User is logged out by default

    def login(self, password):
        if self.password == password:
            self.is_logged_in = True
            print(f"User {self.email} logged in successfully.")
        else:
            print(f"Login failed for user {self.email}")

    def logout(self):
        self.is_logged_in = False
        print(f"User {self.email} logged out.")


def change_email(user, old_email, new_email, password):
    """
    Attempts to change a user's email address after performing security checks.

    Args:
        user: The user object attempting the change.
        old_email: The user's claimed old email address.
        new_email: The desired new email address.
        password: The user's password for confirmation.

    Returns:
        A string indicating success or the specific reason for failure.
    """
    # 1. Check if the user is logged in
    if not user.is_logged_in:
        return "Error: User is not logged in."

    # 2. Check if the provided old email matches the current one
    if user.email != old_email:
        return "Error: Old email does not match the current email."

    # 3. Check if the provided password is correct
    if user.password != password:
        return "Error: Incorrect password."

    # 4. Check if the new email is different from the old email
    if user.email == new_email:
        return "Error: New email cannot be the same as the old email."
    
    # In a real application, you would also validate the new email format.

    # All checks passed, update the email
    user.email = new_email
    return f"Success: Email has been changed to {new_email}"


class Lse56:
    @staticmethod
    def main():
        # --- Test Cases ---
        print("--- Python Test Cases ---")

        # Test Case 1: Successful Email Change
        print("\n--- Test Case 1: Successful Change ---")
        user1 = User("test1@example.com", "password123")
        user1.login("password123")
        result1 = change_email(user1, "test1@example.com", "new1@example.com", "password123")
        print(f"Result: {result1}")
        print(f"User's current email: {user1.email}")
        user1.logout()

        # Test Case 2: User Not Logged In
        print("\n--- Test Case 2: User Not Logged In ---")
        user2 = User("test2@example.com", "password456")
        # user2 does not log in
        result2 = change_email(user2, "test2@example.com", "new2@example.com", "password456")
        print(f"Result: {result2}")
        print(f"User's current email: {user2.email}")

        # Test Case 3: Incorrect Old Email
        print("\n--- Test Case 3: Incorrect Old Email ---")
        user3 = User("test3@example.com", "password789")
        user3.login("password789")
        result3 = change_email(user3, "wrong-email@example.com", "new3@example.com", "password789")
        print(f"Result: {result3}")
        print(f"User's current email: {user3.email}")
        user3.logout()

        # Test Case 4: Incorrect Password
        print("\n--- Test Case 4: Incorrect Password ---")
        user4 = User("test4@example.com", "securepass")
        user4.login("securepass")
        result4 = change_email(user4, "test4@example.com", "new4@example.com", "wrongpass")
        print(f"Result: {result4}")
        print(f"User's current email: {user4.email}")
        user4.logout()

        # Test Case 5: New Email is Same as Old Email
        print("\n--- Test Case 5: New Email is Same as Old Email ---")
        user5 = User("test5@example.com", "pass12345")
        user5.login("pass12345")
        result5 = change_email(user5, "test5@example.com", "test5@example.com", "pass12345")
        print(f"Result: {result5}")
        print(f"User's current email: {user5.email}")
        user5.logout()

if __name__ == "__main__":
    Lse56.main()