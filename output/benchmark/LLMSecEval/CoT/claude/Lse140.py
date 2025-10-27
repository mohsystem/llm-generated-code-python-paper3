
import mysql.connector
from mysql.connector import Error

class Lse140:
    DB_HOST = "localhost"
    DB_NAME = "testdb"
    DB_USER = "root"
    DB_PASSWORD = "password"
    
    @staticmethod
    def check_username_exists(username):
        if not username or not username.strip():
            return False
        
        conn = None
        cursor = None
        
        try:
            conn = mysql.connector.connect(
                host=Lse140.DB_HOST,
                database=Lse140.DB_NAME,
                user=Lse140.DB_USER,
                password=Lse140.DB_PASSWORD
            )
            
            cursor = conn.cursor(prepared=True)
            query = "SELECT COUNT(*) FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            return result[0] > 0 if result else False
            
        except Error as e:
            print("Database error occurred")
            return False
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

def main():
    test_users = ["admin", "john_doe", "'; DROP TABLE users; --", 
                  "user123", "nonexistent"]
    
    print("Testing username existence:")
    for user in test_users:
        exists = Lse140.check_username_exists(user)
        print(f"Username '{user}' exists: {exists}")

if __name__ == "__main__":
    main()
