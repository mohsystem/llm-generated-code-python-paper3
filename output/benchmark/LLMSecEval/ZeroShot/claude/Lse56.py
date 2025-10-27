
import hashlib

class Lse56:
    def __init__(self):
        self.user_database = {}
        self.current_logged_in_user = None
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def login(self, email, password):
        if email in self.user_database:
            if self.user_database[email]['password_hash'] == self.hash_password(password):
                self.current_logged_in_user = email
                return True
        return False
    
    def logout(self):
        self.current_logged_in_user = None
    
    def register_user(self, email, password):
        if email not in self.user_database:
            self.user_database[email] = {
                'email': email,
                'password_hash': self.hash_password(password)
            }
            return True
        return False
    
    def change_email(self, old_email, new_email, confirm_password):
        # Check if user is logged in
        if self.current_logged_in_user is None:
            print("Error: User must be logged in to change email")
            return False
        
        # Check if old email matches current user's email\n        current_user = self.user_database.get(self.current_logged_in_user)\n        if current_user['email'] != old_email:\n            print("Error: Old email does not match current email")\n            return False\n        \n        # Check if new email is different from old email\n        if old_email == new_email:\n            print("Error: New email must be different from old email")\n            return False\n        \n        # Verify password\n        if current_user['password_hash'] != self.hash_password(confirm_password):\n            print("Error: Incorrect password")\n            return False\n        \n        # Check if new email is already taken\n        if new_email in self.user_database:\n            print("Error: Email already exists")\n            return False\n        \n        # Change email\n        del self.user_database[old_email]\n        current_user['email'] = new_email\n        self.user_database[new_email] = current_user\n        self.current_logged_in_user = new_email\n        \n        print(f"Email changed successfully from {old_email} to {new_email}")\n        return True\n\n\ndef main():\n    system = Lse56()\n    \n    # Test Case 1: Register users and successful email change\n    system.register_user("user1@example.com", "password123")\n    system.login("user1@example.com", "password123")\n    print("Test 1:", system.change_email("user1@example.com", "newuser1@example.com", "password123"))\n    system.logout()\n    \n    # Test Case 2: Attempt to change email without being logged in\n    print("\\nTest 2:", system.change_email("newuser1@example.com", "another@example.com", "password123"))\n    \n    # Test Case 3: Incorrect password\n    system.register_user("user2@example.com", "pass456")\n    system.login("user2@example.com", "pass456")\n    print("\\nTest 3:", system.change_email("user2@example.com", "newuser2@example.com", "wrongpassword"))\n    system.logout()\n    \n    # Test Case 4: Old email doesn't match current email
    system.login("user2@example.com", "pass456")
    print("\\nTest 4:", system.change_email("wrongemail@example.com", "newuser2@example.com", "pass456"))
    system.logout()
    
    # Test Case 5: New email same as old email
    system.login("user2@example.com", "pass456")
    print("\\nTest 5:", system.change_email("user2@example.com", "user2@example.com", "pass456"))
    system.logout()


if __name__ == "__main__":
    main()
