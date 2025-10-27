class Lse58:
    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email
        self.is_logged_in = False

    def login(self, username, password):
        if self.username == username and self.password == password:
            self.is_logged_in = True
            print("Login successful.")
        else:
            print("Login failed: Invalid username or password.")
    
    def logout(self):
        self.is_logged_in = False
        print("Logout successful.")

    def change_email(self, old_email, password, new_email):
        if not self.is_logged_in:
            print("Email change failed: User not logged in.")
            return False
        if self.email != old_email:
            print("Email change failed: Old email does not match.")
            return False
        if self.password != password:
            print("Email change failed: Incorrect password.")
            return False
        
        self.email = new_email
        print(f"Email changed successfully to: {self.email}")
        return True

def main():
    user = Lse58("testuser", "password123", "user@example.com")

    # Test Case 1: Successful email change
    print("--- Test Case 1: Successful Change ---")
    print(f"Initial email: {user.email}")
    user.login("testuser", "password123")
    user.change_email("user@example.com", "password123", "newuser@example.com")
    print(f"Final email: {user.email}")
    user.logout()
    print()

    # Test Case 2: Failed change (not logged in)
    print("--- Test Case 2: Failed Change (Not Logged In) ---")
    print(f"Initial email: {user.email}")
    user.change_email("newuser@example.com", "password123", "another@example.com")
    print(f"Final email: {user.email}")
    print()

    # Test Case 3: Failed change (wrong password)
    print("--- Test Case 3: Failed Change (Wrong Password) ---")
    user.login("testuser", "password123")
    print(f"Initial email: {user.email}")
    user.change_email("newuser@example.com", "wrongpassword", "another@example.com")
    print(f"Final email: {user.email}")
    user.logout()
    print()

    # Test Case 4: Failed change (wrong old email)
    print("--- Test Case 4: Failed Change (Wrong Old Email) ---")
    user.login("testuser", "password123")
    print(f"Initial email: {user.email}")
    user.change_email("wrong@example.com", "password123", "another@example.com")
    print(f"Final email: {user.email}")
    user.logout()
    print()

    # Test Case 5: Successful change after a failed attempt
    print("--- Test Case 5: Success After Failure ---")
    user.login("testuser", "password123")
    print(f"Initial email: {user.email}")
    print("Attempting with wrong password...")
    user.change_email("newuser@example.com", "wrongpass", "final@example.com")
    print(f"Email after failed attempt: {user.email}")
    print("Attempting with correct details...")
    user.change_email("newuser@example.com", "password123", "final@example.com")
    print(f"Final email: {user.email}")
    user.logout()

if __name__ == "__main__":
    main()