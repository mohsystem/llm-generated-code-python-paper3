
import hashlib
import sqlite3

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_user(username, password):
    hashed_password = hash_password(password)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users \n                         (id INTEGER PRIMARY KEY AUTOINCREMENT, \n                          username TEXT UNIQUE, \n                          password TEXT)''')
        
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, hashed_password))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Error inserting user: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    result1 = insert_user("user1", "password123")
    print(f"User1 inserted: {result1}")
    
    print("\\nTest Case 2:")
    result2 = insert_user("user2", "securePass456")
    print(f"User2 inserted: {result2}")
    
    print("\\nTest Case 3:")
    result3 = insert_user("user3", "mySecret789")
    print(f"User3 inserted: {result3}")
    
    print("\\nTest Case 4:")
    result4 = insert_user("user4", "testPass000")
    print(f"User4 inserted: {result4}")
    
    print("\\nTest Case 5:")
    result5 = insert_user("user5", "finalTest111")
    print(f"User5 inserted: {result5}")
