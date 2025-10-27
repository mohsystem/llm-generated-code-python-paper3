
import sqlite3
import html
from datetime import datetime
from typing import Dict, Optional

class Lse150:
    MAX_USERNAME_LENGTH = 50
    MAX_MESSAGE_LENGTH = 500
    
    @staticmethod
    def get_connection():
        """Simulated database connection"""
        return sqlite3.connect('messages.db')
    
    @staticmethod
    def sanitize_input(input_str: Optional[str]) -> str:
        """Sanitize input to prevent XSS"""
        if input_str is None:
            return ""
        return html.escape(input_str.strip())
    
    @staticmethod
    def validate_input(username: Optional[str], message: Optional[str]) -> bool:
        """Validate input parameters"""
        return (username is not None and 
                len(username.strip()) > 0 and 
                len(username) <= Lse150.MAX_USERNAME_LENGTH and
                message is not None and 
                len(message.strip()) > 0 and 
                len(message) <= Lse150.MAX_MESSAGE_LENGTH)
    
    @staticmethod
    def insert_user_message_in_db(username: str, message: str) -> bool:
        """Securely insert message into database"""
        try:
            conn = Lse150.get_connection()
            cursor = conn.cursor()
            
            sanitized_username = Lse150.sanitize_input(username)
            sanitized_message = Lse150.sanitize_input(message)
            
            cursor.execute(
                "INSERT INTO messages (username, message, created_at) VALUES (?, ?, ?)",
                (sanitized_username, sanitized_message, datetime.now())
            )
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def post(request: Dict[str, str]) -> str:
        """Handle post request"""
        username = request.get('username')
        message = request.get('message')
        
        if not Lse150.validate_input(username, message):
            return "error.html?msg=Invalid input"
        
        if Lse150.insert_user_message_in_db(username, message):
            return "redirect:/index.html"
        else:
            return "error.html?msg=Failed to save message"
    
    @staticmethod
    def get_main_page_form() -> str:
        """Generate HTML form"""
        return """<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n<title>Message Board</title>\n</head>\n<body>\n<h1>Submit a Message</h1>\n<form method="POST" action="/post">\n  <label>Username:</label><br>\n  <input type="text" name="username" maxlength="50" required><br><br>\n  <label>Message:</label><br>\n  <textarea name="message" maxlength="500" required></textarea><br><br>\n  <input type="submit" value="Submit">\n</form>\n</body>\n</html>"""


# Test cases
if __name__ == "__main__":
    print("Test Case 1: Valid input")
    req1 = {'username': 'John', 'message': 'Hello World'}
    print(Lse150.post(req1))
    
    print("\\nTest Case 2: Empty username")
    req2 = {'username': '', 'message': 'Test message'}
    print(Lse150.post(req2))
    
    print("\\nTest Case 3: None message")
    req3 = {'username': 'Alice', 'message': None}
    print(Lse150.post(req3))
    
    print("\\nTest Case 4: XSS attempt")
    req4 = {'username': "<script>alert('xss')</script>", 'message': 'Normal message'}
    print(Lse150.post(req4))
    
    print("\\nTest Case 5: Long input")
    req5 = {'username': 'A' * 60, 'message': 'Test'}
    print(Lse150.post(req5))
