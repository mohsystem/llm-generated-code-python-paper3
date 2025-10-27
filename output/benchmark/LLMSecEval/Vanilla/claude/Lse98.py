
import hashlib
import sqlite3

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    hashed_password = hash_password(password)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                         (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                          username TEXT UNIQUE,\n                          password TEXT)''')
        
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                      (username, hashed_password))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Test Case 1:", register_user("alice", "password123"))
    print("Test Case 2:", register_user("bob", "securePass456"))
    print("Test Case 3:", register_user("charlie", "mySecret789"))
    print("Test Case 4:", register_user("diana", "test@2024"))
    print("Test Case 5:", register_user("eve", "strongPwd!"))
