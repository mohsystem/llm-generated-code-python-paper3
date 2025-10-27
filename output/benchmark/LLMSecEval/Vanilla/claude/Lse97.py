
import sqlite3
import hashlib

conn = None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, first_name, last_name, email):
    global conn
    try:
        # Initialize SQLite connection if not exists
        if conn is None:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users \n                            (username TEXT PRIMARY KEY, password TEXT, firstName TEXT, lastName TEXT, email TEXT)''')
            conn.commit()
        
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result:
            return "Username already exists"
        
        # Hash password
        hashed_password = hash_password(password)
        
        # Insert user
        cursor.execute("INSERT INTO users (username, password, firstName, lastName, email) VALUES (?, ?, ?, ?, ?)",
                      (username, hashed_password, first_name, last_name, email))
        conn.commit()
        
        return "Registration succeeded"
    except sqlite3.Error as e:
        return f"Registration failed: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print(register_user("john_doe", "password123", "John", "Doe", "john@example.com"))
    print(register_user("jane_smith", "securePass456", "Jane", "Smith", "jane@example.com"))
    print(register_user("john_doe", "anotherPass", "John", "Doe", "john2@example.com"))
    print(register_user("bob_wilson", "bobPass789", "Bob", "Wilson", "bob@example.com"))
    print(register_user("alice_brown", "alicePass321", "Alice", "Brown", "alice@example.com"))
    
    if conn:
        conn.close()
