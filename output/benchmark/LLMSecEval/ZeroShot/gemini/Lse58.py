import hashlib
import os
import base64

class Lse58:
    def __init__(self):
        self.users = {}
        self.current_user = None

    def _hash_password(self, password, salt):
        """
        Hashes a password with a given salt using SHA-256.
        WARNING: For a real-world application, use a stronger, adaptive hashing function
        like Argon2, scrypt, or bcrypt (e.g., via the 'passlib' library), 
        which are more resistant to brute-force attacks.
        """
        # In Python, password and salt should be bytes for hashing
        pwd_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(pwd_bytes)
        return hasher.digest()

    def register_user(self, username, password, email):
        if not username or not password or username in self.users:
            return False
        
        salt = os.urandom(16)
        hashed_password = self._hash_password(password, salt)
        
        # Store salt and hash encoded as strings for easier handling (e.g., in JSON/DB)
        self.users[username] = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'hashed_password': base64.b64encode(hashed_password).decode('utf-8'),
            'email': email
        }
        return True

    def login(self, username, password):
        user = self.users.get(username)
        if user:
            salt = base64.b64decode(user['salt'])
            hashed_password = self._hash_password(password, salt)
            stored_hash = base64.b64decode(user['hashed_password'])
            
            # In a real application, use a constant-time comparison function
            # (e.g., hmac.compare_digest) to prevent timing attacks.
            if hashed_password == stored_hash:
                self.current_user = username
                return True
        return False

    def logout(self):
        self.current_user = None

    def change_email(self, old_email, password, new_email):
        if not self.current_user:
            return False

        user_data = self.users.get(self.current_user)
        if not user_data:
            # Should not happen if current_user is set correctly
            return False

        if user_data['email'] != old_email:
            return False
            
        salt = base64.b64decode(user_data['salt'])
        hashed_password = self._hash_password(password, salt)
        stored_hash = base64.b64decode(user_data['hashed_password'])

        if hashed_password != stored_hash:
            return False
            
        # All checks passed, update email
        user_data['email'] = new_email
        return True

def main():
    system = Lse58()
    test_user = "testuser"
    test_pass = "Password123!"
    test_email = "test@example.com"
    
    print(f"Registering user: {test_user}")
    system.register_user(test_user, test_pass, test_email)

    # Test Case 1: Successful login and email change.
    print("\n--- Test Case 1: Successful Change ---")
    logged_in = system.login(test_user, test_pass)
    print(f"Login successful: {logged_in}")
    if logged_in:
        email_changed = system.change_email(test_email, test_pass, "new@example.com")
        print(f"Email change successful: {email_changed}")
        print(f"User's new email: {system.users[system.current_user]['email']}")
    system.logout()

    # Test Case 2: Attempt to change email with the wrong password.
    print("\n--- Test Case 2: Wrong Password ---")
    logged_in = system.login(test_user, test_pass)
    print(f"Login successful: {logged_in}")
    if logged_in:
        email_changed = system.change_email("new@example.com", "WrongPassword!", "another@example.com")
        print(f"Email change successful: {email_changed}")
        print(f"User's email remains: {system.users[system.current_user]['email']}")
    system.logout()

    # Test Case 3: Attempt to change email with the wrong old email.
    print("\n--- Test Case 3: Wrong Old Email ---")
    logged_in = system.login(test_user, test_pass)
    print(f"Login successful: {logged_in}")
    if logged_in:
        email_changed = system.change_email("wrong@example.com", test_pass, "another@example.com")
        print(f"Email change successful: {email_changed}")
        print(f"User's email remains: {system.users[system.current_user]['email']}")
    system.logout()

    # Test Case 4: Attempt to change email when not logged in.
    print("\n--- Test Case 4: Not Logged In ---")
    email_changed = system.change_email("new@example.com", test_pass, "another@example.com")
    print(f"Email change successful: {email_changed}")

    # Test Case 5: Successful change after a failed attempt.
    print("\n--- Test Case 5: Successful Change After Failed Attempt ---")
    logged_in = system.login(test_user, test_pass)
    print(f"Login successful: {logged_in}")
    if logged_in:
        failed_change = system.change_email("new@example.com", "badpass", "final@example.com")
        print(f"First change attempt (should fail): {failed_change}")
        success_change = system.change_email("new@example.com", test_pass, "final@example.com")
        print(f"Second change attempt (should succeed): {success_change}")
        print(f"User's final email: {system.users[system.current_user]['email']}")
    system.logout()

if __name__ == "__main__":
    main()