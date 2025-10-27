
import uuid
from typing import Dict, Optional

class Lse52:
    def __init__(self):
        # Predefined users for testing
        self.user_database = {
            "admin": "admin123",
            "user1": "password1",
            "user2": "password2",
            "testuser": "testpass",
            "demo": "demo123"
        }
        self.sessions = {}
    
    def render_login_page(self, error: Optional[str] = None) -> str:
        html = "<html><body>"
        html += "<h2>Login Page</h2>"
        if error:
            html += f"<p style='color:red;'>{error}</p>"
        html += "<form method='post' action='/login'>"
        html += "Username: <input type='text' name='username' required><br>"
        html += "Password: <input type='password' name='password' required><br>"
        html += "<input type='submit' value='Login'>"
        html += "</form>"
        html += "<a href='/'>Back to Home</a>"
        html += "</body></html>"
        return html
    
    def render_index_page(self) -> str:
        return ("<html><body><h2>Welcome to Index Page</h2>"
                "<a href='/login'>Go to Login</a></body></html>")
    
    def render_secret_page(self, username: str) -> str:
        return (f"<html><body><h2>Secret settings</h2>"
                f"<p>Welcome, {username}!</p>"
                f"<a href='/logout'>Logout</a></body></html>")
    
    def do_login(self, username: Optional[str], password: Optional[str]) -> bool:
        if username is None or password is None:
            return False
        stored_password = self.user_database.get(username)
        return stored_password is not None and stored_password == password
    
    def create_session(self, username: str) -> str:
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = username
        return session_id
    
    def get_user_from_session(self, session_id: str) -> Optional[str]:
        return self.sessions.get(session_id)
    
    def logout(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]


def main():
    app = Lse52()
    print("=== Login System Test Cases ===\\n")
    
    # Test Case 1: Valid login
    print("Test Case 1: Valid login")
    result1 = app.do_login("admin", "admin123")
    print(f"Result: {'SUCCESS' if result1 else 'FAILED'}")
    if result1:
        session1 = app.create_session("admin")
        print(f"Session created: {session1}")
        print(app.render_secret_page("admin"))
    print()
    
    # Test Case 2: Invalid password
    print("Test Case 2: Invalid password")
    result2 = app.do_login("admin", "wrongpass")
    print(f"Result: {'SUCCESS' if result2 else 'FAILED'}")
    print()
    
    # Test Case 3: Non-existent user
    print("Test Case 3: Non-existent user")
    result3 = app.do_login("nonexistent", "password")
    print(f"Result: {'SUCCESS' if result3 else 'FAILED'}")
    print()
    
    # Test Case 4: Valid login with different user
    print("Test Case 4: Valid login with user1")
    result4 = app.do_login("user1", "password1")
    print(f"Result: {'SUCCESS' if result4 else 'FAILED'}")
    if result4:
        session4 = app.create_session("user1")
        print(f"Session created: {session4}")
    print()
    
    # Test Case 5: Null credentials
    print("Test Case 5: Null credentials")
    result5 = app.do_login(None, None)
    print(f"Result: {'SUCCESS' if result5 else 'FAILED'}")
    print()
    
    # Display pages
    print("=== Page Renders ===\\n")
    print("Index Page:")
    print(app.render_index_page())
    print("\\nLogin Page:")
    print(app.render_login_page(None))


if __name__ == "__main__":
    main()
