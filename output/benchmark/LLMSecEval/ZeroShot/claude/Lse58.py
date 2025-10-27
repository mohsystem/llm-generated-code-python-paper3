
import hashlib
import re

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = self._hash_password(password)
        self.logged_in = False
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def login(self, password):
        if self._hash_password(password) == self.password_hash:
            self.logged_in = True
            return True
        return False
    
    def logout(self):
        self.logged_in = False
    
    def change_email(self, old_email, password, new_email):
        if not self.logged_in:
            return False
        if self.email != old_email:
            return False
        if self._hash_password(password) != self.password_hash:
            return False
        if not new_email or not self._is_valid_email(new_email):
            return False
        self.email = new_email
        return True
    
    def _is_valid_email(self, email):
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return re.match(pattern, email) is not None
    
    def get_email(self):
        return self.email
    
    def get_username(self):
        return self.username
    
    def is_logged_in(self):
        return self.logged_in

def main():
    # Test Case 1: Successful email change
    user1 = User("john_doe", "john@example.com", "password123")
    user1.login("password123")
    result1 = user1.change_email("john@example.com", "password123", "newemail@example.com")
    print(f"Test 1 - Successful change: {result1}, New email: {user1.get_email()}")
    
    # Test Case 2: Wrong old email
    user2 = User("jane_doe", "jane@example.com", "securepass")
    user2.login("securepass")
    result2 = user2.change_email("wrong@example.com", "securepass", "newemail@example.com")
    print(f"Test 2 - Wrong old email: {result2}, Email unchanged: {user2.get_email()}")
    
    # Test Case 3: Wrong password
    user3 = User("bob_smith", "bob@example.com", "mypassword")
    user3.login("mypassword")
    result3 = user3.change_email("bob@example.com", "wrongpassword", "newemail@example.com")
    print(f"Test 3 - Wrong password: {result3}, Email unchanged: {user3.get_email()}")
    
    # Test Case 4: Not logged in
    user4 = User("alice_wonder", "alice@example.com", "alicepass")
    result4 = user4.change_email("alice@example.com", "alicepass", "newemail@example.com")
    print(f"Test 4 - Not logged in: {result4}, Email unchanged: {user4.get_email()}")
    
    # Test Case 5: Invalid new email format
    user5 = User("charlie_brown", "charlie@example.com", "charpass")
    user5.login("charpass")
    result5 = user5.change_email("charlie@example.com", "charpass", "invalidemail")
    print(f"Test 5 - Invalid email format: {result5}, Email unchanged: {user5.get_email()}")

if __name__ == "__main__":
    main()
