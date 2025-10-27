
class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

users = {}
logged_in_user = None

def register(username, email, password):
    global users
    if username in users:
        return False
    users[username] = User(username, email, password)
    return True

def login(username, password):
    global logged_in_user
    if username in users and users[username].password == password:
        logged_in_user = users[username]
        return True
    return False

def logout():
    global logged_in_user
    logged_in_user = None

def change_email(old_email, new_email, password):
    global logged_in_user
    if logged_in_user is None:
        return False
    
    if logged_in_user.email == old_email and logged_in_user.password == password:
        logged_in_user.email = new_email
        return True
    return False

def get_current_email():
    if logged_in_user is not None:
        return logged_in_user.email
    return None

if __name__ == "__main__":
    # Test Case 1: Register and login, then change email successfully
    print("Test Case 1:")
    register("user1", "user1@example.com", "password123")
    login("user1", "password123")
    result1 = change_email("user1@example.com", "newemail1@example.com", "password123")
    print(f"Change email result: {result1}, New email: {get_current_email()}")
    logout()
    
    # Test Case 2: Try to change email without logging in
    print("\\nTest Case 2:")
    result2 = change_email("user1@example.com", "newemail2@example.com", "password123")
    print(f"Change email without login: {result2}")
    
    # Test Case 3: Login but provide wrong old email
    print("\\nTest Case 3:")
    login("user1", "password123")
    result3 = change_email("wrong@example.com", "newemail3@example.com", "password123")
    print(f"Change email with wrong old email: {result3}, Current email: {get_current_email()}")
    logout()
    
    # Test Case 4: Login but provide wrong password
    print("\\nTest Case 4:")
    login("user1", "password123")
    result4 = change_email("newemail1@example.com", "newemail4@example.com", "wrongpassword")
    print(f"Change email with wrong password: {result4}, Current email: {get_current_email()}")
    logout()
    
    # Test Case 5: Successful email change with correct credentials
    print("\\nTest Case 5:")
    register("user2", "user2@example.com", "pass456")
    login("user2", "pass456")
    result5 = change_email("user2@example.com", "user2new@example.com", "pass456")
    print(f"Change email result: {result5}, New email: {get_current_email()}")
    logout()
