
import hashlib

class Lse57:
    def __init__(self):
        self.users = {}
        self.logged_in_user = None
    
    class User:
        def __init__(self, email, password):
            self.email = email
            self.password_hash = Lse57.hash_password(password)
    
    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register(self, email, password):
        if email in self.users:
            return False
        self.users[email] = self.User(email, password)
        return True
    
    def login(self, email, password):
        user = self.users.get(email)
        if user and user.password_hash == self.hash_password(password):
            self.logged_in_user = email
            return True
        return False
    
    def change_email(self, old_email, new_email, confirm_password):
        # Check if user is logged in
        if self.logged_in_user is None:
            return False
        
        # Check if old email matches logged in user's email\n        if self.logged_in_user != old_email:\n            return False\n        \n        # Check if old email exists\n        user = self.users.get(old_email)\n        if user is None:\n            return False\n        \n        # Verify confirm password\n        if user.password_hash != self.hash_password(confirm_password):\n            return False\n        \n        # Check if new email already exists\n        if new_email in self.users:\n            return False\n        \n        # Change email\n        del self.users[old_email]\n        user.email = new_email\n        self.users[new_email] = user\n        self.logged_in_user = new_email\n        \n        return True\n    \n    def logout(self):\n        self.logged_in_user = None\n\n\nif __name__ == "__main__":\n    # Test Case 1: Successful email change\n    print("Test Case 1: Successful email change")\n    system1 = Lse57()\n    system1.register("user1@example.com", "password123")\n    system1.login("user1@example.com", "password123")\n    result1 = system1.change_email("user1@example.com", "newuser1@example.com", "password123")\n    print(f"Result: {result1} (Expected: True)")\n    system1.logout()\n    \n    # Test Case 2: Not logged in\n    print("\\nTest Case 2: Not logged in")\n    system2 = Lse57()\n    system2.register("user2@example.com", "password456")\n    result2 = system2.change_email("user2@example.com", "newuser2@example.com", "password456")\n    print(f"Result: {result2} (Expected: False)")\n    \n    # Test Case 3: Wrong confirm password\n    print("\\nTest Case 3: Wrong confirm password")\n    system3 = Lse57()\n    system3.register("user3@example.com", "password789")\n    system3.login("user3@example.com", "password789")\n    result3 = system3.change_email("user3@example.com", "newuser3@example.com", "wrongpassword")\n    print(f"Result: {result3} (Expected: False)")\n    system3.logout()\n    \n    # Test Case 4: Old email doesn't match logged in user
    print("\\nTest Case 4: Old email doesn't match logged in user")
    system4 = Lse57()
    system4.register("user4@example.com", "password111")
    system4.register("user5@example.com", "password222")
    system4.login("user4@example.com", "password111")
    result4 = system4.change_email("user5@example.com", "newuser5@example.com", "password222")
    print(f"Result: {result4} (Expected: False)")
    system4.logout()
    
    # Test Case 5: New email already exists
    print("\\nTest Case 5: New email already exists")
    system5 = Lse57()
    system5.register("user6@example.com", "password333")
    system5.register("user7@example.com", "password444")
    system5.login("user6@example.com", "password333")
    result5 = system5.change_email("user6@example.com", "user7@example.com", "password333")
    print(f"Result: {result5} (Expected: False)")
    system5.logout()
