
import hashlib
import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    'host': 'localhost',
    'database': 'userdb',
    'user': 'root',
    'password': 'password'
}

def hash_password(password):
    """Hash the password using SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def update_password(username, new_password):
    """Update user password in database"""
    hashed_password = hash_password(new_password)
    
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        sql = "UPDATE users SET password = %s WHERE username = %s"
        cursor.execute(sql, (hashed_password, username))
        
        connection.commit()
        rows_affected = cursor.rowcount
        
        cursor.close()
        connection.close()
        
        return rows_affected > 0
        
    except Error as e:
        print(f"Database error: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    result1 = update_password("john_doe", "newPassword123")
    print(f"Update result for john_doe: {result1}")
    
    print("\\nTest Case 2:")
    result2 = update_password("jane_smith", "SecurePass456!")
    print(f"Update result for jane_smith: {result2}")
    
    print("\\nTest Case 3:")
    result3 = update_password("admin", "Admin@2024")
    print(f"Update result for admin: {result3}")
    
    print("\\nTest Case 4:")
    result4 = update_password("test_user", "TestPass789#")
    print(f"Update result for test_user: {result4}")
    
    print("\\nTest Case 5:")
    result5 = update_password("guest", "GuestPassword2024")
    print(f"Update result for guest: {result5}")
