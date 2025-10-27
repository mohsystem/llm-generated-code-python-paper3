
class User:
    def __init__(self, username, password, is_admin):
        self.username = username
        self.__password = password
        self.is_admin = is_admin
    
    def check_password(self, password):
        return self.__password == password

class Session:
    def __init__(self):
        self.current_user = None
    
    def login(self, user):
        self.current_user = user
    
    def logout(self):
        self.current_user = None
    
    def is_logged_in(self):
        return self.current_user is not None
    
    def get_current_user(self):
        return self.current_user

def redirect_user(session):
    if not session.is_logged_in():
        return "Redirect to: /login"
    
    user = session.get_current_user()
    if user.is_admin:
        return "Redirect to: /admin"
    else:
        return "Redirect to: /user"

def authenticate(username, password, user_database):
    user = user_database.get(username)
    if user and user.check_password(password):
        return True
    return False

if __name__ == "__main__":
    # Create user database
    user_database = {
        "admin": User("admin", "admin123", True),
        "john": User("john", "john123", False),
        "jane": User("jane", "jane123", False)
    }
    
    session = Session()
    
    # Test Case 1: Not logged in
    print("Test Case 1 - Not logged in:")
    print(redirect_user(session))
    print()
    
    # Test Case 2: Logged in as regular user (john)
    print("Test Case 2 - Logged in as regular user (john):")
    if authenticate("john", "john123", user_database):
        session.login(user_database["john"])
    print(redirect_user(session))
    session.logout()
    print()
    
    # Test Case 3: Logged in as admin
    print("Test Case 3 - Logged in as admin:")
    if authenticate("admin", "admin123", user_database):
        session.login(user_database["admin"])
    print(redirect_user(session))
    session.logout()
    print()
    
    # Test Case 4: Failed login attempt
    print("Test Case 4 - Failed login attempt:")
    if authenticate("john", "wrongpassword", user_database):
        session.login(user_database["john"])
    print(redirect_user(session))
    print()
    
    # Test Case 5: Logged in as another regular user (jane)
    print("Test Case 5 - Logged in as regular user (jane):")
    if authenticate("jane", "jane123", user_database):
        session.login(user_database["jane"])
    print(redirect_user(session))
    print()
