import sqlite3
import hashlib
import secrets
import base64
import re
from typing import Tuple


class Lse35:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password with SHA-256 and salt"""
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, 100000)
        return base64.b64encode(password_hash).decode()

    @staticmethod
    def generate_salt() -> str:
        """Generate secure random salt"""
        return base64.b64encode(secrets.token_bytes(16)).decode()

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Secure login function with input validation and prepared statements.
        Returns: (success: bool, redirect_url: str)
        """
        # Input validation
        if not username or not password:
            return False, "login.html?error=empty"

        # Sanitize username (alphanumeric only, 3–20 characters)
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return False, "login.html?error=invalid"

        # Password length check
        if len(password) < 8 or len(password) > 128:
            return False, "login.html?error=invalid"

        conn = None
        try:
            # Connect to database with read-only mode for security
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Use parameterized query to prevent SQL injection
            query = "SELECT password_hash, salt FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                stored_hash, salt = result

                # Hash input password with stored salt
                input_hash = self.hash_password(password, salt)

                # Constant-time comparison to prevent timing attacks
                if secrets.compare_digest(input_hash, stored_hash):
                    return True, "home.html"

            # Invalid credentials (don’t reveal if user exists)
            return False, "login.html?error=invalid"

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False, "login.html?error=system"

        finally:
            if conn:
                conn.close()


def main():
    """Test cases for login functionality"""
    login_system = Lse35()

    print("Test Case 1 - Valid user:")
    success, redirect = login_system.login("validuser", "correctpassword")
    print(f"Success: {success}, Redirect: {redirect}")

    print("\nTest Case 2 - Invalid password:")
    success, redirect = login_system.login("validuser", "wrongpassword")
    print(f"Success: {success}, Redirect: {redirect}")

    print("\nTest Case 3 - Non-existent user:")
    success, redirect = login_system.login("nonexistent", "anypassword")
    print(f"Success: {success}, Redirect: {redirect}")

    print("\nTest Case 4 - Empty username:")
    success, redirect = login_system.login("", "password")
    print(f"Success: {success}, Redirect: {redirect}")

    print("\nTest Case 5 - SQL injection attempt:")
    success, redirect = login_system.login("admin' OR '1'='1", "password")
    print(f"Success: {success}, Redirect: {redirect}")


if __name__ == "__main__":
    main()
