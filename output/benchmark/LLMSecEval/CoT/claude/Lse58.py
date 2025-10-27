
import hashlib
import secrets
import base64
import re

class User:
    def __init__(self, email, password):
        self.email = email
        self.salt = self._generate_salt()
        self.password_hash = self._hash_password(password, self.salt)
        self.is_logged_in = False
    
    def _generate_salt(self):
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def _hash_password(self, password, salt):
        hash_obj = hashlib.sha256()
        hash_obj.update(salt.encode())
        hash_obj.update(password.encode())
        return base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    def login(self, email, password):
        if self.email == email and self.password_hash == self._hash_password(password, self.salt):
            self.is_logged_in = True
            return True
        return False
    
    def logout(self):
        self.is_logged_in = False
    
    def change_email(self, old_email, password, new_email):
        if not self.is_logged_in:
            print("Error: User must be logged in to change email")
            return False
        
        if not new_email or not new_email.strip() or not self._is_valid_email(new_email):
            print("Error: Invalid new email format")
            return False
        
        if self.email != old_email:
            print("Error: Old email does not match")
            return False
        
        if self.password_hash != self._hash_password(password, self.salt):
            print("Error: Incorrect password")
            return False
        
        self.email = new_email
        print(f"Email successfully changed to: {new_email}")
        return True
    
    def _is_valid_email(self, email):
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return re.match(pattern, email) is not None
    
    def get_email(self):
        return self.email
    
    def is_user_logged_in(self):
        return self.is_logged_in


if __name__ == "__main__":
    print("=== Test Case 1: Successful email change ===")
    user1 = User("user1@example.com", "password123")
    user1.login("user1@example.com", "password123")
    user1.change_email("user1@example.com", "password123", "newemail1@example.com")
    print(f"Current email: {user1.get_email()}\\n")
    
    print("=== Test Case 2: Wrong old email ===")
    user2 = User("user2@example.com", "password456")
    user2.login("user2@example.com", "password456")
    user2.change_email("wrong@example.com", "password456", "newemail2@example.com")
    print(f"Current email: {user2.get_email()}\\n")
    
    print("=== Test Case 3: Wrong password ===")
    user3 = User("user3@example.com", "password789")
    user3.login("user3@example.com", "password789")
    user3.change_email("user3@example.com", "wrongpassword", "newemail3@example.com")
    print(f"Current email: {user3.get_email()}\\n")
    
    print("=== Test Case 4: Not logged in ===")
    user4 = User("user4@example.com", "password000")
    user4.change_email("user4@example.com", "password000", "newemail4@example.com")
    print(f"Current email: {user4.get_email()}\\n")
    
    print("=== Test Case 5: Invalid new email format ===")
    user5 = User("user5@example.com", "password111")
    user5.login("user5@example.com", "password111")
    user5.change_email("user5@example.com", "password111", "invalidemail")
    print(f"Current email: {user5.get_email()}\\n")
