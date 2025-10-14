
import hashlib
import secrets
import time
import re
from typing import Dict, Optional, Tuple

class Task40:
    def __init__(self):
        self.session_tokens: Dict[str, Tuple[str, float]] = {}
        self.user_database: Dict[str, Dict[str, str]] = {}
        self.TOKEN_VALIDITY = 3600  # 1 hour in seconds
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate a cryptographically secure CSRF token"""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Session ID cannot be None or empty")
        
        # Generate secure random token
        token = secrets.token_urlsafe(32)
        timestamp = time.time()
        
        # Store token with timestamp
        self.session_tokens[session_id] = (token, timestamp)
        
        return token
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token using constant-time comparison"""
        if not session_id or not token:
            return False
        
        stored_data = self.session_tokens.get(session_id)
        if not stored_data:
            return False
        
        stored_token, timestamp = stored_data
        
        # Check token expiry
        if time.time() - timestamp > self.TOKEN_VALIDITY:
            del self.session_tokens[session_id]
            return False
        
        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(stored_token, token)
    
    def sanitize_input(self, input_str: str, max_length: int = 255) -> str:
        """Sanitize input to prevent XSS attacks"""
        if not input_str:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'&]', '', input_str)
        sanitized = sanitized.strip()
        
        # Limit length
        return sanitized[:max_length]
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return bool(re.match(pattern, email))
    
    def update_user_settings(self, session_id: str, csrf_token: str, 
                            username: str, email: str, theme: str) -> str:
        """Update user settings with CSRF protection"""
        
        # Input validation
        if not username or not username.strip():
            return "Error: Username cannot be empty"
        
        if not self.validate_email(email):
            return "Error: Invalid email format"
        
        if not theme or not theme.strip():
            return "Error: Theme cannot be empty"
        
        # CSRF Token validation (critical security check)
        if not self.validate_csrf_token(session_id, csrf_token):
            return "Error: Invalid CSRF token. Request rejected for security reasons."
        
        # Sanitize inputs to prevent XSS
        username = self.sanitize_input(username)
        email = self.sanitize_input(email)
        theme = self.sanitize_input(theme)
        
        # Update user settings
        self.user_database[session_id] = {
            'username': username,
            'email': email,
            'theme': theme
        }
        
        # Invalidate the used token and generate a new one
        del self.session_tokens[session_id]
        new_token = self.generate_csrf_token(session_id)
        
        return f"Success: Settings updated. New CSRF token: {new_token}"


def main():
    print("=== CSRF-Protected User Settings Update Demo ===\\n")
    
    app = Task40()
    
    # Test Case 1: Valid update with correct CSRF token
    print("Test Case 1: Valid update")
    session1 = f"session_{secrets.token_hex(8)}"
    token1 = app.generate_csrf_token(session1)
    print(f"Generated CSRF Token: {token1}")
    result1 = app.update_user_settings(session1, token1, "john_doe", "john@example.com", "dark")
    print(f"{result1}\\n")
    
    # Test Case 2: Invalid CSRF token (should fail)
    print("Test Case 2: Invalid CSRF token")
    session2 = f"session_{secrets.token_hex(8)}"
    app.generate_csrf_token(session2)
    result2 = app.update_user_settings(session2, "invalid_token_12345", "jane_doe", "jane@example.com", "light")
    print(f"{result2}\\n")
    
    # Test Case 3: Reusing token (should fail)
    print("Test Case 3: Token reuse attempt")
    session3 = f"session_{secrets.token_hex(8)}"
    token3 = app.generate_csrf_token(session3)
    app.update_user_settings(session3, token3, "alice", "alice@example.com", "blue")
    result3 = app.update_user_settings(session3, token3, "alice_updated", "alice2@example.com", "red")
    print(f"{result3}\\n")
    
    # Test Case 4: Invalid email format
    print("Test Case 4: Invalid email format")
    session4 = f"session_{secrets.token_hex(8)}"
    token4 = app.generate_csrf_token(session4)
    result4 = app.update_user_settings(session4, token4, "bob", "invalid-email", "green")
    print(f"{result4}\\n")
    
    # Test Case 5: Empty username
    print("Test Case 5: Empty username")
    session5 = f"session_{secrets.token_hex(8)}"
    token5 = app.generate_csrf_token(session5)
    result5 = app.update_user_settings(session5, token5, "", "test@example.com", "yellow")
    print(f"{result5}\\n")


if __name__ == "__main__":
    main()
