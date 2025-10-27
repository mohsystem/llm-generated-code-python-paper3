import hashlib
import secrets
import re

class User:
    def __init__(self, username, email, password_hash, salt):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt

class UserService:
    def __init__(self):
        self._users = {}
        self._logged_in_user = None
        # Simple regex for email validation
        self._email_pattern = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

    def _hash_password(self, password, salt):
        """Hashes password with PBKDF2."""
        # Rules #7, #8, #9, #10: Use strong KDF with salt
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # Iteration count
            dklen=128
        )

    def _verify_password(self, password, stored_hash, salt):
        """Verifies a password against a stored hash and salt."""
        return secrets.compare_digest(
            stored_hash,
            self._hash_password(password, salt)
        )

    def register_user(self, username, password, email):
        """Registers a new user."""
        # Rule #1: Input validation
        if not (username and password and email and self._email_pattern.match(email)):
            print("Registration failed: Invalid input.")
            return False
        if username in self._users:
            print(f"Registration failed: Username '{username}' already exists.")
            return False

        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(password, salt)
        self._users[username] = User(username, email, password_hash, salt)
        print(f"User '{username}' registered successfully.")
        return True

    def login(self, username, password):
        """Logs a user in."""
        user = self._users.get(username)
        if user and self._verify_password(password, user.password_hash, user.salt):
            self._logged_in_user = user
            print(f"'{username}' logged in successfully.")
            return True
        print(f"Login failed for '{username}'.")
        return False

    def logout(self):
        """Logs the current user out."""
        if self._logged_in_user:
            print(f"'{self._logged_in_user.username}' logged out.")
            self._logged_in_user = None
            
    def change_email(self, old_email, new_email, confirm_password):
        """Changes the email for the logged-in user."""
        # Rule #1: Input validation
        if not (old_email and new_email and confirm_password and self._email_pattern.match(new_email)):
            print("Email change failed: Invalid input provided.")
            return False

        if not self._logged_in_user:
            print("Email change failed: User must be logged in.")
            return False
        
        if self._logged_in_user.email != old_email:
            print("Email change failed: Old email does not match.")
            return False

        if not self._verify_password(confirm_password, self._logged_in_user.password_hash, self._logged_in_user.salt):
            print("Email change failed: Incorrect password.")
            return False
        
        self._logged_in_user.email = new_email
        print(f"Email for user '{self._logged_in_user.username}' changed successfully to '{new_email}'.")
        return True

    def print_user_details(self, username):
        user = self._users.get(username)
        if user:
            print(f"Details for {username}: Email = {user.email}")
        else:
            print(f"User {username} not found.")

def main():
    service = UserService()

    # Setup: Register a user
    service.register_user("py_user", "PyPass123$", "initial_py@example.com")
    print("----------------------------------------")
    
    # Test Case 1: Successful email change
    print("Test Case 1: Successful email change")
    service.login("py_user", "PyPass123$")
    service.print_user_details("py_user")
    service.change_email("initial_py@example.com", "updated_py@example.com", "PyPass123$")
    service.print_user_details("py_user")
    service.logout()
    print("----------------------------------------")

    # Test Case 2: Attempt to change email when not logged in
    print("Test Case 2: Attempt change when not logged in")
    service.change_email("updated_py@example.com", "another_py@example.com", "PyPass123$")
    service.print_user_details("py_user")
    print("----------------------------------------")

    # Test Case 3: Attempt to change email with wrong password
    print("Test Case 3: Attempt change with wrong password")
    service.login("py_user", "PyPass123$")
    service.change_email("updated_py@example.com", "another_py@example.com", "WrongPassword!")
    service.print_user_details("py_user")
    service.logout()
    print("----------------------------------------")

    # Test Case 4: Attempt to change email with wrong old email
    print("Test Case 4: Attempt change with wrong old email")
    service.login("py_user", "PyPass123$")
    service.change_email("wrong.old_py@example.com", "another_py@example.com", "PyPass123$")
    service.print_user_details("py_user")
    service.logout()
    print("----------------------------------------")
    
    # Test Case 5: Attempt to change to an invalid new email
    print("Test Case 5: Attempt change to an invalid new email")
    service.login("py_user", "PyPass123$")
    service.change_email("updated_py@example.com", "invalid-email", "PyPass123$")
    service.print_user_details("py_user")
    service.logout()
    print("----------------------------------------")

if __name__ == "__main__":
    main()