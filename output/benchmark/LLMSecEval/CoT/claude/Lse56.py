
import hashlib
import secrets
import re
from typing import Optional, Dict

class Lse56:
    def __init__(self):
        self.users: Dict[str, Dict] = {}
        self.current_logged_in_user: Optional[Dict] = None
        self.email_pattern = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    
    def _generate_salt(self) -> str:
        return secrets.token_hex(16)
    
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    
    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        return secrets.compare_digest(
            self._hash_password(password, salt),
            password_hash
        )
    
    def _is_valid_email(self, email: str) -> bool:
        return email is not None and self.email_pattern.match(email) is not None
    
    def register_user(self, email: str, password: str) -> bool:
        if not self._is_valid_email(email) or not password:
            return False
        
        if email in self.users:
            return False
        
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        
        self.users[email] = {
            'email': email,
            'password_hash': password_hash,
            'salt': salt
        }
        return True
    
    def login(self, email: str, password: str) -> bool:
        if not self._is_valid_email(email) or not password:
            return False
        
        user = self.users.get(email)
        if user and self._verify_password(password, user['password_hash'], user['salt']):
            self.current_logged_in_user = user
            return True
        return False
    
    def logout(self):
        self.current_logged_in_user = None
    
    def is_logged_in(self) -> bool:
        return self.current_logged_in_user is not None
    
    def change_email(self, old_email: str, new_email: str, confirm_password: str) -> str:
        if not self.is_logged_in():
            return "Error: User must be logged in to change email"
        
        if not self._is_valid_email(old_email) or not self._is_valid_email(new_email):
            return "Error: Invalid email format"
        
        if not confirm_password:
            return "Error: Password is required"
        
        if self.current_logged_in_user['email'] != old_email:
            return "Error: Old email does not match current user email"
        
        if old_email == new_email:
            return "Error: New email must be different from old email"
        
        if not self._verify_password(confirm_password, 
                                     self.current_logged_in_user['password_hash'],
                                     self.current_logged_in_user['salt']):
            return "Error: Incorrect password"
        
        if new_email in self.users:
            return "Error: New email already exists"
        
        del self.users[old_email]
        self.current_logged_in_user['email'] = new_email
        self.users[new_email] = self.current_logged_in_user
        
        return "Success: Email changed successfully"


if __name__ == "__main__":
    system = Lse56()
    
    # Test Case 1: Register and login successfully
    system.register_user("user@example.com", "SecurePass123")
    print("Test 1 - Login:", system.login("user@example.com", "SecurePass123"))
    
    # Test Case 2: Change email successfully
    print("Test 2 - Change Email:", 
          system.change_email("user@example.com", "newemail@example.com", "SecurePass123"))
    
    # Test Case 3: Try to change email with wrong password
    system.logout()
    system.login("newemail@example.com", "SecurePass123")
    print("Test 3 - Wrong Password:", 
          system.change_email("newemail@example.com", "another@example.com", "WrongPass"))
    
    # Test Case 4: Try to change email to same email
    print("Test 4 - Same Email:", 
          system.change_email("newemail@example.com", "newemail@example.com", "SecurePass123"))
    
    # Test Case 5: Try to change email without being logged in
    system.logout()
    print("Test 5 - Not Logged In:", 
          system.change_email("newemail@example.com", "test@example.com", "SecurePass123"))
