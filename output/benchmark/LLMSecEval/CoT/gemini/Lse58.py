class Lse58:
    def __init__(self, username, password, email):
        self.username = username
        # In a real app, this should be a hashed password
        self.password = password
        self.email = email
        self.is_logged_in = False

    def login(self, username, password):
        if self.username == username and self.password == password:
            self.is_logged_in = True
            print(f"Login successful for user: {self.username}")
            return True
        print(f"Login failed for user: {username}")
        return False

    def logout(self):
        self.is_logged_in = False
        print(f"{self.username} has been logged out.")

    def change_email(self, old_email, confirm_password, new_email):
        if not self.is_logged_in:
            print("Error: You must be logged in to change your email.")
            return False

        if self.email == old_email and self.password == confirm_password:
            self.email = new_email
            print(f"Success: Email has been changed to {new_email}")
            return True
        else:
            print("Error: Incorrect old email or password. Email not changed.")
            return False

    def get_email(self):
        return self.email

if __name__ == "__main__":
    user = Lse58("testuser", "password123", "user@example.com")

    print("--- Test Case 1: Successful Email Change ---")
    user.login("testuser", "password123")
    user.change_email("user@example.com", "password123", "newuser@example.com")
    print(f"Current email: {user.get_email()}")
    user.logout()
    print()

    # Reset user for next tests
    user = Lse58("testuser", "password123", "user@example.com")
    
    print("--- Test Case 2: Failed Change (Not Logged In) ---")
    user.change_email("user@example.com", "password123", "another@example.com")
    print(f"Current email: {user.get_email()}")
    print()

    print("--- Test Case 3: Failed Change (Wrong Password) ---")
    user.login("testuser", "password123")
    user.change_email("user@example.com", "wrongpassword", "another@example.com")
    print(f"Current email: {user.get_email()}")
    user.logout()
    print()
    
    # Reset user
    user = Lse58("testuser", "password123", "user@example.com")
    
    print("--- Test Case 4: Failed Change (Wrong Old Email) ---")
    user.login("testuser", "password123")
    user.change_email("wrong@example.com", "password123", "another@example.com")
    print(f"Current email: {user.get_email()}")
    print()

    print("--- Test Case 5: Failed Change (Logged out then attempt) ---")
    user.logout() # Ensuring user is logged out
    user.change_email("user@example.com", "password123", "final@example.com")
    print(f"Current email: {user.get_email()}")