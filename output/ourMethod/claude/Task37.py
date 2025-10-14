
import re
import os
from typing import Optional
import sqlite3

MAX_USERNAME_LENGTH = 50
USERNAME_PATTERN = r'^[a-zA-Z0-9_-]+$'


def get_user_info(username: str) -> str:
    """\n    Retrieve user information from database based on username.\n    \n    Args:\n        username: The username to search for\n        \n    Returns:\n        String containing user information or error message\n    """
    if username is None or username == "":
        return "Error: Username cannot be null or empty"
    
    if len(username) > MAX_USERNAME_LENGTH:
        return "Error: Username exceeds maximum length"
    
    if not re.match(USERNAME_PATTERN, username):
        return "Error: Username contains invalid characters"
    
    db_path = os.environ.get('DB_PATH', 'users.db')
    
    if not db_path or not isinstance(db_path, str):
        return "Error: Invalid database path"
    
    query = "SELECT id, username, email, created_at FROM users WHERE username = ?"
    
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            
            if row:
                user_id = row['id']
                user_name = row['username']
                email = row['email']
                created_at = row['created_at']
                
                return f"User found - ID: {user_id}, Username: {user_name}, Email: {email}, Created: {created_at}"
            else:
                return "User not found"
                
    except sqlite3.Error:
        return "Error: Database operation failed"
    except Exception:
        return "Error: Unexpected error occurred"


def main() -> None:
    """Run test cases for the get_user_info function."""
    print("Test Case 1 - Valid username:")
    print(get_user_info("john_doe"))
    print()
    
    print("Test Case 2 - Valid username with numbers:")
    print(get_user_info("user123"))
    print()
    
    print("Test Case 3 - Invalid username with special chars:")
    print(get_user_info("user'; DROP TABLE users--"))
    print()
    
    print("Test Case 4 - None username:")
    print(get_user_info(None))
    print()
    
    print("Test Case 5 - Empty username:")
    print(get_user_info(""))


if __name__ == "__main__":
    main()
