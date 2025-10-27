
import hashlib
import secrets
import base64
import re
import sqlite3

def register_user(username, password, first_name, last_name, email, conn):
    """\n    Registers a new user with secure password hashing\n    """
    # Input validation
    if not all([username, password, first_name, last_name, email]):
        return "Error: All fields are required"
    
    if not username.strip() or not password.strip() or not first_name.strip() or not last_name.strip() or not email.strip():
        return "Error: All fields are required"
    
    # Validate email format
    email_pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    if not re.match(email_pattern, email):
        return "Error: Invalid email format"
    
    # Password strength validation
    if len(password) < 8:
        return "Error: Password must be at least 8 characters"
    
    try:
        cursor = conn.cursor()
        
        # Check if username already exists using parameterized query
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        
        if cursor.fetchone():
            return "Error: Username already exists"
        
        # Generate salt and hash password
        salt = secrets.token_bytes(16)
        hashed_password = hash_password(password, salt)
        salt_string = base64.b64encode(salt).decode('utf-8')
        
        # Insert user into database using parameterized query
        cursor.execute(
            "INSERT INTO users (username, password, salt, first_name, last_name, email) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hashed_password, salt_string, first_name, last_name, email)
        )
        
        conn.commit()
        return "Success: Registration succeeded"
        
    except sqlite3.Error as e:
        return f"Error: Database operation failed - {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def hash_password(password, salt):
    """\n    Hashes password with salt using SHA-256\n    """
    pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return base64.b64encode(pwd_hash).decode('utf-8')

def main():
    """\n    Test cases for the registration system\n    """
    print("Registration System Test Cases:\\n")
    
    # Create in-memory database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            password TEXT NOT NULL,\n            salt TEXT NOT NULL,\n            first_name TEXT NOT NULL,\n            last_name TEXT NOT NULL,\n            email TEXT NOT NULL\n        )\n    ''')
    conn.commit()
    
    # Test Case 1: Valid registration
    print("Test Case 1 - Valid registration:")
    result = register_user("john_doe", "SecurePass123", "John", "Doe", "john@example.com", conn)
    print(f"Result: {result}\\n")
    
    # Test Case 2: Duplicate username
    print("Test Case 2 - Duplicate username:")
    result = register_user("john_doe", "Pass456", "Jane", "Smith", "jane@example.com", conn)
    print(f"Result: {result}\\n")
    
    # Test Case 3: Empty fields
    print("Test Case 3 - Empty fields:")
    result = register_user("", "Pass123", "Test", "User", "test@example.com", conn)
    print(f"Result: {result}\\n")
    
    # Test Case 4: Invalid email
    print("Test Case 4 - Invalid email:")
    result = register_user("testuser", "Pass123", "Test", "User", "invalid-email", conn)
    print(f"Result: {result}\\n")
    
    # Test Case 5: Weak password
    print("Test Case 5 - Weak password:")
    result = register_user("testuser2", "123", "Test", "User", "test2@example.com", conn)
    print(f"Result: {result}\\n")
    
    conn.close()

if __name__ == "__main__":
    main()
