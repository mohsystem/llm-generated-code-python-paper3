
import os
import sqlite3
from typing import Optional

def is_user_moderator(username: str) -> bool:
    """\n    Check if a user is a moderator by querying the database.\n    \n    Args:\n        username: The username to check\n        \n    Returns:\n        True if user is a moderator, False otherwise\n    """
    if not username or not username.strip():
        return False
    
    db_url = os.getenv('DB_URL')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    
    if not all([db_url, db_user, db_password]):
        print("Database credentials not configured", file=__import__('sys').stderr)
        return False
    
    query = "SELECT is_moderator FROM users WHERE username = ? LIMIT 1"
    
    try:
        # For SQLite (adjust connection string for other databases)
        conn = sqlite3.connect(db_url)
        cursor = conn.cursor()
        
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if result:
            return bool(result[0])
        
    except sqlite3.Error as e:
        print("Database error occurred", file=__import__('sys').stderr)
        return False
    except Exception as e:
        print("Unexpected error occurred", file=__import__('sys').stderr)
        return False
    
    return False

if __name__ == "__main__":
    # Test cases
    print(f"Test 1 - Valid moderator: {is_user_moderator('admin')}")
    print(f"Test 2 - Valid non-moderator: {is_user_moderator('user123')}")
    print(f"Test 3 - Non-existent user: {is_user_moderator('nonexistent')}")
    print(f"Test 4 - Null username: {is_user_moderator(None)}")
    print(f"Test 5 - Empty username: {is_user_moderator('')}")
