
import sqlite3
from typing import Optional

def login(username: str, password: str) -> str:
    """\n    Login function that checks username and password against database\n    Returns appropriate message based on authentication result\n    """
    conn = None
    try:
        # Connect to SQLite database (using SQLite for simplicity)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Query to check if username exists
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result:
            stored_password = result[0]
            if stored_password == password:
                return "redirect:home"
            else:
                return "incorrect_password"
        else:
            return "user_not_found"
            
    except sqlite3.Error as e:
        return f"error: {str(e)}"
    finally:
        if conn:
            conn.close()

def setup_test_database():
    """Helper function to setup test database with sample users"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                     (username TEXT PRIMARY KEY, password TEXT)''')
    
    # Insert test users
    test_users = [
        ('admin', 'admin123'),
        ('user1', 'pass123'),
        ('john_doe', 'johnspass'),
        ('testuser', 'testpass'),
        ('demo', 'demo123')
    ]
    
    cursor.execute("DELETE FROM users")
    cursor.executemany("INSERT OR REPLACE INTO users VALUES (?, ?)", test_users)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # Setup test database
    setup_test_database()
    
    # Test cases
    print("Test Case 1:", login("admin", "admin123"))
    print("Test Case 2:", login("user1", "wrongpass"))
    print("Test Case 3:", login("john_doe", "johnspass"))
    print("Test Case 4:", login("nonexistent", "password"))
    print("Test Case 5:", login("testuser", "testpass"))
