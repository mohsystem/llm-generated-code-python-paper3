
import sqlite3
import os

class Lse35:
    DB_NAME = "users.db"
    
    @staticmethod
    def init_database():
        """Initialize database and create users table"""
        conn = sqlite3.connect(Lse35.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL UNIQUE,\n                password TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def add_user(username, password):
        """Add a user to database (for testing)"""
        try:
            conn = sqlite3.connect(Lse35.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                          (username, password))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            pass
    
    @staticmethod
    def login(username, password):
        """Login function"""
        conn = sqlite3.connect(Lse35.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                      (username, password))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return "home.html"  # Redirect to home page
        else:
            return "login.html"  # Redirect to login page

if __name__ == "__main__":
    # Initialize database
    Lse35.init_database()
    
    # Clear existing data and add test users
    conn = sqlite3.connect(Lse35.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    conn.commit()
    conn.close()
    
    Lse35.add_user("admin", "admin123")
    Lse35.add_user("user1", "pass123")
    Lse35.add_user("john", "doe456")
    
    # Test cases
    print("Test Case 1: Valid credentials (admin/admin123)")
    print("Result:", Lse35.login("admin", "admin123"))
    print()
    
    print("Test Case 2: Valid credentials (user1/pass123)")
    print("Result:", Lse35.login("user1", "pass123"))
    print()
    
    print("Test Case 3: Invalid password")
    print("Result:", Lse35.login("admin", "wrongpass"))
    print()
    
    print("Test Case 4: Non-existent user")
    print("Result:", Lse35.login("nonuser", "password"))
    print()
    
    print("Test Case 5: Valid credentials (john/doe456)")
    print("Result:", Lse35.login("john", "doe456"))
