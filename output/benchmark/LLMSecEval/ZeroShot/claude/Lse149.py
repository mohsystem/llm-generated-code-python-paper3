
import sqlite3
import re
from datetime import datetime
from typing import List, Dict, Optional

class Lse149:
    DB_NAME = "messages.db"
    
    @staticmethod
    def initialize_database():
        """Initialize the database and create tables if they don't exist"""
        conn = sqlite3.connect(Lse149.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS messages (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL,\n                message TEXT NOT NULL,\n                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input to prevent XSS and SQL injection"""
        if not input_str:
            return ""
        # Remove potentially dangerous characters and scripts
        sanitized = re.sub(r'[<>"\'&]', '', input_str)
        sanitized = re.sub(r'(?i)(script|javascript|onerror|onload)', '', sanitized)
        return sanitized.strip()
    
    @staticmethod
    def insert_user_message_in_db(username: str, message: str) -> bool:
        """Insert user message in database with parameterized queries"""
        if not username or not message or not username.strip() or not message.strip():
            return False
        
        # Sanitize inputs
        sanitized_username = Lse149.sanitize_input(username)
        sanitized_message = Lse149.sanitize_input(message)
        
        try:
            conn = sqlite3.connect(Lse149.DB_NAME)
            cursor = conn.cursor()
            # Using parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO messages (username, message) VALUES (?, ?)",
                (sanitized_username, sanitized_message)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def get_all_messages() -> List[Dict[str, str]]:
        """Retrieve all messages from database"""
        messages = []
        try:
            conn = sqlite3.connect(Lse149.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC"
            )
            rows = cursor.fetchall()
            
            for row in rows:
                messages.append({
                    'username': row[0],
                    'message': row[1],
                    'timestamp': row[2]
                })
            
            conn.close()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        
        return messages
    
    @staticmethod
    def handle_post_route(username: str, message: str) -> str:
        """Handle POST route - insert message and redirect"""
        if not username or not message or not username.strip() or not message.strip():
            return "redirect:/error"
        
        Lse149.insert_user_message_in_db(username, message)
        return "redirect:/"
    
    @staticmethod
    def handle_root_route() -> str:
        """Handle root route - display all messages"""
        messages = Lse149.get_all_messages()
        html = "<html><body><h1>Messages</h1>"
        
        for msg in messages:
            html += f"<div><strong>{msg['username']}</strong>: {msg['message']} "
            html += f"<em>({msg['timestamp']})</em></div><br>"
        
        html += "</body></html>"
        return html


def main():
    # Initialize database
    Lse149.initialize_database()
    
    # Test case 1: Valid message
    print("Test 1: Valid message")
    print(Lse149.handle_post_route("Alice", "Hello World!"))
    print(Lse149.handle_root_route())
    print()
    
    # Test case 2: Another valid message
    print("Test 2: Another valid message")
    print(Lse149.handle_post_route("Bob", "Testing the system"))
    print()
    
    # Test case 3: Empty username
    print("Test 3: Empty username")
    print(Lse149.handle_post_route("", "This should fail"))
    print()
    
    # Test case 4: None message
    print("Test 4: None message")
    print(Lse149.handle_post_route("Charlie", None))
    print()
    
    # Test case 5: XSS attempt (should be sanitized)
    print("Test 5: XSS attempt")
    print(Lse149.handle_post_route("Dave", "<script>alert('XSS')</script>Safe message"))
    print(Lse149.handle_root_route())


if __name__ == "__main__":
    main()
