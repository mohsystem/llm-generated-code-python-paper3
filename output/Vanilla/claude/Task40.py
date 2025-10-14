
import secrets
import hashlib
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class UserSettings:
    username: str
    email: str
    theme: str
    notifications: bool
    
    def __str__(self):
        return f"UserSettings(username='{self.username}', email='{self.email}', theme='{self.theme}', notifications={self.notifications})"

class Task40:
    def __init__(self):
        self.csrf_tokens: Dict[str, str] = {}
        self.user_database: Dict[str, UserSettings] = {}
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session"""
        token = secrets.token_urlsafe(32)
        self.csrf_tokens[session_id] = token
        return token
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token"""
        stored_token = self.csrf_tokens.get(session_id)
        return stored_token is not None and secrets.compare_digest(stored_token, token)
    
    def generate_settings_form(self, session_id: str, settings: UserSettings) -> str:
        """Generate HTML form with CSRF token"""
        csrf_token = self.generate_csrf_token(session_id)
        
        html = f"""<!DOCTYPE html>\n<html>\n<head>\n    <title>User Settings</title>\n    <style>\n        body {{ font-family: Arial; margin: 20px; }}\n        form {{ max-width: 400px; }}\n        input, select {{ width: 100%; padding: 8px; margin: 5px 0; }}\n    </style>\n</head>\n<body>\n    <h1>Update User Settings</h1>\n    <form method='POST' action='/update-settings'>\n        <input type='hidden' name='csrf_token' value='{csrf_token}'>\n        <label>Username:</label>\n        <input type='text' name='username' value='{settings.username}' required><br>\n        <label>Email:</label>\n        <input type='email' name='email' value='{settings.email}' required><br>\n        <label>Theme:</label>\n        <select name='theme'>\n            <option value='light'{'selected' if settings.theme == 'light' else ''}>Light</option>\n            <option value='dark'{'selected' if settings.theme == 'dark' else ''}>Dark</option>\n        </select><br>\n        <label>\n            <input type='checkbox' name='notifications' {'checked' if settings.notifications else ''}>\n            Enable Notifications\n        </label><br>\n        <input type='submit' value='Update Settings'>\n    </form>\n</body>\n</html>"""
        return html
    
    def process_settings_update(self, session_id: str, csrf_token: str,
                                username: str, email: str, theme: str,
                                notifications: bool) -> str:
        """Process form submission with CSRF validation"""
        if not self.validate_csrf_token(session_id, csrf_token):
            return "ERROR: Invalid CSRF token. Possible CSRF attack detected!"
        
        settings = UserSettings(username, email, theme, notifications)
        self.user_database[session_id] = settings
        
        # Invalidate token after use
        if session_id in self.csrf_tokens:
            del self.csrf_tokens[session_id]
        
        return f"SUCCESS: Settings updated successfully - {settings}"
    
    def get_user_settings(self, session_id: str) -> UserSettings:
        """Get user settings"""
        return self.user_database.get(session_id,
            UserSettings("john_doe", "john@example.com", "light", True))

def main():
    print("=== CSRF Protection Demo - Web Application ===\\n")
    app = Task40()
    
    # Test Case 1: Generate form for new session
    print("Test Case 1: Generate form with CSRF token")
    session1 = f"session_{secrets.token_hex(8)}"
    settings1 = app.get_user_settings(session1)
    form = app.generate_settings_form(session1, settings1)
    print(f"Form generated with CSRF token (showing first 200 chars):")
    print(form[:200] + "...\\n")
    
    # Test Case 2: Valid update with correct CSRF token
    print("Test Case 2: Valid update with correct CSRF token")
    session2 = "session_user2"
    token2 = app.generate_csrf_token(session2)
    result2 = app.process_settings_update(session2, token2, "alice",
                                          "alice@example.com", "dark", False)
    print(result2 + "\\n")
    
    # Test Case 3: Invalid update with wrong CSRF token
    print("Test Case 3: Invalid update with wrong CSRF token")
    session3 = "session_user3"
    app.generate_csrf_token(session3)
    result3 = app.process_settings_update(session3, "invalid_token", "bob",
                                          "bob@example.com", "light", True)
    print(result3 + "\\n")
    
    # Test Case 4: Token reuse attempt
    print("Test Case 4: Token reuse attempt")
    session4 = "session_user4"
    token4 = app.generate_csrf_token(session4)
    app.process_settings_update(session4, token4, "charlie",
                               "charlie@example.com", "dark", True)
    result4 = app.process_settings_update(session4, token4, "charlie_changed",
                                          "charlie2@example.com", "light", False)
    print(result4 + "\\n")
    
    # Test Case 5: Multiple users with different tokens
    print("Test Case 5: Multiple concurrent sessions")
    session5a = "session_user5a"
    session5b = "session_user5b"
    token5a = app.generate_csrf_token(session5a)
    token5b = app.generate_csrf_token(session5b)
    result5a = app.process_settings_update(session5a, token5a, "david",
                                           "david@example.com", "light", True)
    result5b = app.process_settings_update(session5b, token5b, "eve",
                                           "eve@example.com", "dark", False)
    print(f"User A: {result5a}")
    print(f"User B: {result5b}")

if __name__ == "__main__":
    main()
