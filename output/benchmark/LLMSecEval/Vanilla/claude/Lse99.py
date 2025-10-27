
import hashlib
import sqlite3

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_user(username, password):
    try:
        hashed_password = hash_password(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users \n                         (id INTEGER PRIMARY KEY AUTOINCREMENT, \n                          username TEXT UNIQUE, \n                          password TEXT)''')
        
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, hashed_password))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print("Success" if insert_user("user1", "password123") else "Failed")
    
    print("\\nTest Case 2:")
    print("Success" if insert_user("user2", "securePass456") else "Failed")
    
    print("\\nTest Case 3:")
    print("Success" if insert_user("admin", "admin@2024") else "Failed")
    
    print("\\nTest Case 4:")
    print("Success" if insert_user("testuser", "test1234") else "Failed")
    
    print("\\nTest Case 5:")
    print("Success" if insert_user("john_doe", "mySecret99") else "Failed")
