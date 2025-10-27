
import hashlib
import re

class User:
    def __init__(self, email, password):
        self.email = email
        self.password_hash = self._hash_password(password)
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password):
        return self.password_hash == self._hash_password(password)

class Lse57:
    def __init__(self):
        self.user_database = {}
        self.logged_in_user = None
    
    def register_user(self, email, password):
        if email not in self.user_database:
            new_user = User(email, password)
            self.user_database[email] = new_user
            return True
        return False
    
    def login(self, email, password):
        if email in self.user_database:
            user = self.user_database[email]
            if user.verify_password(password):
                self.logged_in_user = user
                return True
        return False
    
    def logout(self):
        self.logged_in_user = None
    
    def is_valid_email(self, email):
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return re.match(pattern, email) is not None
    
    def change_email(self, old_email, new_email, confirm_password):
        # Check if user is logged in
        if self.logged_in_user is None:
            return "Error: User not logged in"
        
        # Verify old email matches logged in user's email
        if self.logged_in_user.email != old_email:
            return "Error: Old email does not match current user email"
        
        # Verify old email exists in database
        if old_email not in self.user_database:
            return "Error: Old email does not exist"
        
        # Verify confirm password is correct
        if not self.logged_in_user.verify_password(confirm_password):
            return "Error: Incorrect password"
        
        # Check if new email is already in use
        if new_email in self.user_database and new_email != old_email:
            return "Error: New email already exists"
        
        # Validate email format
        if not self.is_valid_email(new_email):
            return "Error: Invalid email format"
        
        # Change email
        del self.user_database[old_email]
        self.logged_in_user.email = new_email
        self.user_database[new_email] = self.logged_in_user
        
        return "Success: Email changed successfully"

def main():
    system = Lse57()
    
    # Test Case 1: Successful email change
    print("Test Case 1: Successful email change")
    system.register_user("user1@example.com", "password123")
    system.login("user1@example.com", "password123")
    result1 = system.change_email("user1@example.com", "newuser1@example.com", "password123")
    print(result1)
    system.logout()
    print()
    
    # Test Case 2: User not logged in
    print("Test Case 2: User not logged in")
    result2 = system.change_email("user2@example.com", "newuser2@example.com", "password123")
    print(result2)
    print()
    
    # Test Case 3: Wrong password
    print("Test Case 3: Wrong password")
    system.register_user("user3@example.com", "password456")
    system.login("user3@example.com", "password456")
    result3 = system.change_email("user3@example.com", "newuser3@example.com", "wrongpassword")
    print(result3)
    system.logout()
    print()
    
    # Test Case 4: Old email mismatch
    print("Test Case 4: Old email mismatch")
    system.register_user("user4@example.com", "password789")
    system.login("user4@example.com", "password789")
    result4 = system.change_email("different@example.com", "newuser4@example.com", "password789")
    print(result4)
    system.logout()
    print()
    
    # Test Case 5: New email already exists
    print("Test Case 5: New email already exists")
    system.register_user("user5@example.com", "password101")
    system.register_user("existing@example.com", "password102")
    system.login("user5@example.com", "password101")
    result5 = system.change_email("user5@example.com", "existing@example.com", "password101")
    print(result5)
    system.logout()

if __name__ == "__main__":
    main()
