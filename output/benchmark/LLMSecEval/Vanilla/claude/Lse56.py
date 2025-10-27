
class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

users = {}
current_logged_in_user = None

def login(username, password):
    global current_logged_in_user
    if username in users:
        user = users[username]
        if user.password == password:
            current_logged_in_user = username
            return True
    return False

def logout():
    global current_logged_in_user
    current_logged_in_user = None

def register_user(username, email, password):
    if username not in users:
        users[username] = User(username, email, password)
        return True
    return False

def change_email(old_email, new_email, confirm_password):
    global current_logged_in_user
    
    # Check if user is logged in
    if current_logged_in_user is None:
        return "Error: User must be logged in to change email"
    
    user = users[current_logged_in_user]
    
    # Check if old email matches
    if user.email != old_email:
        return "Error: Old email does not match"
    
    # Check if password is correct
    if user.password != confirm_password:
        return "Error: Incorrect password"
    
    # Check if new email is different from old email
    if old_email == new_email:
        return "Error: New email must be different from old email"
    
    # Change email
    user.email = new_email
    return "Success: Email changed successfully"

if __name__ == "__main__":
    # Test Case 1: Change email successfully
    print("Test Case 1:")
    register_user("user1", "old@example.com", "password123")
    login("user1", "password123")
    print(change_email("old@example.com", "new@example.com", "password123"))
    logout()
    print()
    
    # Test Case 2: Try to change email without logging in
    print("Test Case 2:")
    print(change_email("old@example.com", "new2@example.com", "password123"))
    print()
    
    # Test Case 3: Wrong old email
    print("Test Case 3:")
    register_user("user2", "user2@example.com", "pass456")
    login("user2", "pass456")
    print(change_email("wrong@example.com", "new@example.com", "pass456"))
    logout()
    print()
    
    # Test Case 4: Wrong password
    print("Test Case 4:")
    register_user("user3", "user3@example.com", "mypass")
    login("user3", "mypass")
    print(change_email("user3@example.com", "newuser3@example.com", "wrongpass"))
    logout()
    print()
    
    # Test Case 5: New email same as old email
    print("Test Case 5:")
    register_user("user4", "user4@example.com", "secure123")
    login("user4", "secure123")
    print(change_email("user4@example.com", "user4@example.com", "secure123"))
    logout()
