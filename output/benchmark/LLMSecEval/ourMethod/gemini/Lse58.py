import os
import hashlib
import hmac

class User:
    def __init__(self, username, email, password):
        if not all([username, email, password]):
            raise ValueError("Username, email, and password cannot be empty.")
        self.username = username
        self.email = email
        # Use a cryptographically secure random number generator for the salt
        self._salt = os.urandom(16)
        self._password_hash = self._hash_password(password)

    def _hash_password(self, password):
        """Hashes the password with the salt using PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self._salt,
            260000  # OWASP recommended iterations
        )

    def verify_password(self, password):
        """Verifies a password against the stored hash in a constant time."""
        if not password:
            return False
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(self._password_hash, self._hash_password(password))

class LoginSystem:
    def __init__(self):
        self._current_user = None
        self._is_logged_in = False

    def register(self, username, email, password):
        """Registers a new user. In this simple system, it overwrites any existing user."""
        try:
            self._current_user = User(username, email, password)
            self._is_logged_in = False
            print(f"User '{username}' registered successfully.")
            return True
        except ValueError as e:
            print(f"Registration failed: {e}")
            return False

    def login(self, username, password):
        """Logs the user in after verifying credentials."""
        if self._current_user and self._current_user.username == username:
            if self._current_user.verify_password(password):
                self._is_logged_in = True
                print(f"Login successful for user '{username}'.")
                return True
        
        self._is_logged_in = False
        print("Login failed: Invalid username or password.")
        return False

    def logout(self):
        """Logs the user out."""
        self._is_logged_in = False
        print("User logged out.")

    def change_email(self, old_email, password, new_email):
        """Changes the user's email after re-authentication."""
        if not self._is_logged_in:
            print("Email change failed: User is not logged in.")
            return False
        
        if not new_email or not new_email.strip():
            print("Email change failed: New email cannot be empty.")
            return False

        # Re-authenticate user before sensitive action
        if self._current_user.email != old_email:
            print("Email change failed: Old email does not match.")
            return False
        
        if not self._current_user.verify_password(password):
            print("Email change failed: Incorrect password.")
            return False
        
        self._current_user.email = new_email
        print(f"Email for '{self._current_user.username}' changed successfully to '{new_email}'.")
        return True
    
    def get_current_user_email(self):
        """Returns the current user's email if logged in, otherwise None."""
        if self._is_logged_in and self._current_user:
            return self._current_user.email
        return None

def main():
    """Main function with test cases."""
    system = LoginSystem()

    # Setup a user. In a real app, passwords would not be hardcoded.
    system.register("testuser", "initial@example.com", "Password123!")

    print("\n--- Test Case 1: Successful Email Change ---")
    system.login("testuser", "Password123!")
    print(f"Current email: {system.get_current_user_email()}")
    system.change_email("initial@example.com", "Password123!", "new@example.com")
    print(f"New email: {system.get_current_user_email()}")
    system.logout()

    print("\n--- Test Case 2: Change Email with Wrong Password ---")
    system.login("testuser", "Password123!")
    print(f"Current email: {system.get_current_user_email()}")
    system.change_email("new@example.com", "WrongPassword!", "another@example.com")
    print(f"Email after failed attempt: {system.get_current_user_email()}")
    system.logout()

    print("\n--- Test Case 3: Change Email with Wrong Old Email ---")
    system.login("testuser", "Password123!")
    print(f"Current email: {system.get_current_user_email()}")
    system.change_email("wrong.old@example.com", "Password123!", "another@example.com")
    print(f"Email after failed attempt: {system.get_current_user_email()}")
    system.logout()

    print("\n--- Test Case 4: Change Email When Not Logged In ---")
    print(f"Current email before attempt: {system.get_current_user_email() or 'N/A'}")
    system.change_email("new@example.com", "Password123!", "another@example.com")
    system.login("testuser", "Password123!")
    print(f"Email after failed attempt: {system.get_current_user_email()}")
    system.logout()

    print("\n--- Test Case 5: Login with Wrong Password ---")
    system.login("testuser", "NotThePassword")
    system.change_email("new@example.com", "Password123!", "another@example.com")

if __name__ == "__main__":
    main()