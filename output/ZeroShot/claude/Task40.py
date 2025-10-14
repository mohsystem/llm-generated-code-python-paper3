
import secrets
import hashlib
import re
from typing import Dict, Optional, Tuple

class Task40:
    def __init__(self):
        self.csrf_token_store: Dict[str, str] = {}
        self.user_database: Dict[str, 'UserSettings'] = {}
    
    class UserSettings:
        def __init__(self, username: str, email: str, theme: str, notifications: bool):
            self.username = username
            self.email = email
            self.theme = theme
            self.notifications = notifications
        
        def __str__(self):
            return f"UserSettings{{username='{self.username}', email='{self.email}', theme='{self.theme}', notifications={self.notifications}}}"
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate a secure CSRF token"""
        token = secrets.token_urlsafe(32)
        self.csrf_token_store[session_id] = token
        return token
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token"""
        if not session_id or not token:
            return False
        stored_token = self.csrf_token_store.get(session_id)
        return stored_token is not None and secrets.compare_digest(stored_token, token)
    
    def get_csrf_token_for_session(self, session_id: str) -> str:
        """Get or generate CSRF token for session"""
        if session_id not in self.csrf_token_store:
            return self.generate_csrf_token(session_id)
        return self.csrf_token_store[session_id]
    
    def update_user_settings(self, session_id: str, csrf_token: str, 
                            username: str, email: str, 
                            theme: str, notifications: bool) -> str:
        """Update user settings with CSRF protection"""
        # Validate CSRF token
        if not self.validate_csrf_token(session_id, csrf_token):
            return "ERROR: Invalid CSRF token. Request rejected."
        
        # Validate input
        if not username or not username.strip():
            return "ERROR: Username cannot be empty."
        
        email_pattern = r'^[A-Za-z0-9+_.-]+@(.+)$'
        if not email or not re.match(email_pattern, email):
            return "ERROR: Invalid email format."
        
        # Update user settings
        settings = self.UserSettings(username, email, theme, notifications)
        self.user_database[session_id] = settings
        
        # Generate new CSRF token after successful update
        self.generate_csrf_token(session_id)
        
        return f"SUCCESS: User settings updated successfully. {settings}"
    
    def generate_settings_form(self, session_id: str) -> str:
        """Generate HTML form with CSRF token"""
        csrf_token = self.get_csrf_token_for_session(session_id)
        current_settings = self.user_database.get(session_id, 
            self.UserSettings("", "", "light", True))
        
        html = f"""<!DOCTYPE html>\n<html>\n<head>\n<title>User Settings</title>\n<style>body{{font-family:Arial;padding:20px;}}</style>\n</head>\n<body>\n<h2>Update User Settings</h2>\n<form method='POST' action='/update-settings'>\n  <input type='hidden' name='csrf_token' value='{csrf_token}'>\n  <label>Username:</label><br>\n  <input type='text' name='username' value='{current_settings.username}' required><br><br>\n  <label>Email:</label><br>\n  <input type='email' name='email' value='{current_settings.email}' required><br><br>\n  <label>Theme:</label><br>\n  <select name='theme'>\n    <option value='light'{'selected' if current_settings.theme == 'light' else ''}>Light</option>\n    <option value='dark'{'selected' if current_settings.theme == 'dark' else ''}>Dark</option>\n  </select><br><br>\n  <label><input type='checkbox' name='notifications'{'checked' if current_settings.notifications else ''}> Enable Notifications</label><br><br>\n  <button type='submit'>Update Settings</button>\n</form>\n</body>\n</html>"""
        
        return html


def main():
    app = Task40()
    print("=== Web Application CSRF Protection Test Cases ===\\n")
    
    # Test Case 1: Valid CSRF token - should succeed
    print("Test Case 1: Valid CSRF token")
    session1 = "session_user1"
    token1 = app.generate_csrf_token(session1)
    result1 = app.update_user_settings(session1, token1, "john_doe", "john@example.com", "dark", True)
    print(result1)
    print()
    
    # Test Case 2: Invalid CSRF token - should fail
    print("Test Case 2: Invalid CSRF token")
    session2 = "session_user2"
    app.generate_csrf_token(session2)
    result2 = app.update_user_settings(session2, "invalid_token_12345", "jane_doe", "jane@example.com", "light", False)
    print(result2)
    print()
    
    # Test Case 3: Missing CSRF token - should fail
    print("Test Case 3: Missing CSRF token")
    session3 = "session_user3"
    app.generate_csrf_token(session3)
    result3 = app.update_user_settings(session3, None, "alice", "alice@example.com", "dark", True)
    print(result3)
    print()
    
    # Test Case 4: Invalid email format - should fail
    print("Test Case 4: Invalid email format")
    session4 = "session_user4"
    token4 = app.generate_csrf_token(session4)
    result4 = app.update_user_settings(session4, token4, "bob", "invalid-email", "light", False)
    print(result4)
    print()
    
    # Test Case 5: Valid update with all fields
    print("Test Case 5: Valid update with all fields")
    session5 = "session_user5"
    token5 = app.generate_csrf_token(session5)
    result5 = app.update_user_settings(session5, token5, "charlie_brown", "charlie@example.com", "light", True)
    print(result5)
    print()
    
    # Demonstrate form generation
    print("Test Case 6: Generate Settings Form HTML")
    form_html = app.generate_settings_form(session1)
    print(f"Form generated (first 200 chars): {form_html[:200]}...")


if __name__ == "__main__":
    main()
