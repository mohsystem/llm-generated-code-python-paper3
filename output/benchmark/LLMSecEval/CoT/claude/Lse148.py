
import sqlite3
import html
from datetime import datetime
from typing import Optional, List, Dict

class Lse148:
    MAX_USERNAME_LENGTH = 50
    MAX_MESSAGE_LENGTH = 500
    DB_NAME = "messages.db"
    
    @staticmethod
    def validate_and_sanitize_input(input_str: Optional[str], max_length: int) -> Optional[str]:
        """Validate and sanitize user input"""
        if not input_str or not input_str.strip():
            return None
        
        sanitized = input_str.strip()
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized
    
    @staticmethod
    def insert_user_message_in_db(username: str, message: str) -> bool:
        """Securely insert message into database using parameterized query"""
        try:
            conn = sqlite3.connect(Lse148.DB_NAME)
            cursor = conn.cursor()
            
            # Using parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
                (username, message, datetime.now())
            )
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def post(request: Dict[str, str]) -> bool:
        """Handle POST request for message submission"""
        try:
            username = request.get('username')
            message = request.get('message')
            
            # Validate and sanitize inputs
            username = Lse148.validate_and_sanitize_input(
                username, 
                Lse148.MAX_USERNAME_LENGTH
            )
            message = Lse148.validate_and_sanitize_input(
                message, 
                Lse148.MAX_MESSAGE_LENGTH
            )
            
            if not username or not message:
                print("Invalid input: username or message is empty")
                return False
            
            # Insert into database
            if Lse148.insert_user_message_in_db(username, message):
                print("Redirecting to: /main")
                return True
            
            return False
            
        except Exception as e:
            print(f"Error in post: {e}")
            return False
    
    @staticmethod
    def html_encode(text: str) -> str:
        """Encode HTML entities to prevent XSS"""
        if not text:
            return ""
        return html.escape(text)
    
    @staticmethod
    def display_messages() -> List[str]:
        """Retrieve and display messages securely"""
        messages = []
        
        try:
            conn = sqlite3.connect(Lse148.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100"
            )
            
            for row in cursor.fetchall():
                username = Lse148.html_encode(row[0])
                message = Lse148.html_encode(row[1])
                timestamp = row[2]
                
                messages.append(f"[{timestamp}] {username}: {message}")
            
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Error retrieving messages: {e}")
        
        return messages
    
    @staticmethod
    def init_database():
        """Initialize database with secure schema"""
        try:
            conn = sqlite3.connect(Lse148.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS messages (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT NOT NULL,\n                    message TEXT NOT NULL,\n                    timestamp DATETIME NOT NULL\n                )\n            """)
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Database init error: {e}")


def main():
    Lse148.init_database()
    
    print("=== Test Cases ===\\n")
    
    # Test 1: Valid message
    request1 = {"username": "Alice", "message": "Hello World!"}
    print(f"Test 1 - Valid message: {Lse148.post(request1)}")
    
    # Test 2: Another valid message
    request2 = {"username": "Bob", "message": "This is a test message"}
    print(f"Test 2 - Valid message: {Lse148.post(request2)}")
    
    # Test 3: Empty username (should fail)
    request3 = {"username": "", "message": "Message without user"}
    print(f"Test 3 - Empty username: {Lse148.post(request3)}")
    
    # Test 4: XSS attempt (should be sanitized)
    request4 = {
        "username": "Hacker<script>",
        "message": "Alert<script>alert('XSS')</script>"
    }
    print(f"Test 4 - XSS attempt: {Lse148.post(request4)}")
    
    # Test 5: Very long message (should be truncated)
    request5 = {"username": "Charlie", "message": "A" * 1000}
    print(f"Test 5 - Long message: {Lse148.post(request5)}")
    
    # Display all messages
    print("\\n=== Displaying Messages ===")
    messages = Lse148.display_messages()
    for msg in messages:
        print(msg)


if __name__ == "__main__":
    main()
