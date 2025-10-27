
import sqlite3
from typing import Optional

class Lse37:
    # Simulated database
    mock_database = {
        "admin": "password123",
        "user1": "pass1",
        "user2": "pass2",
        "testuser": "testpass",
        "john": "doe123"
    }
    
    @staticmethod
    def login_user(username: Optional[str], password: Optional[str]) -> str:
        try:
            # Check if username and password are not None or empty
            if not username or not password:
                return "cant_login"
            
            # Check credentials in database
            if username in Lse37.mock_database and Lse37.mock_database[username] == password:
                return "success"
            else:
                return "cant_login"
                
        except Exception as e:
            return "internal_server_error"
    
    @staticmethod
    def login_user_with_db(username: str, password: str, db_path: str = "users.db") -> str:
        conn = None
        try:
            # Establish database connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Prepare SQL query with parameterized statement to prevent SQL injection
            sql = "SELECT * FROM users WHERE username = ? AND password = ?"
            cursor.execute(sql, (username, password))
            
            # Check if user exists
            result = cursor.fetchone()
            
            if result:
                return "success"
            else:
                return "cant_login"
                
        except sqlite3.Error as e:
            return "internal_server_error"
        finally:
            if conn:
                conn.close()


def main():
    # Test case 1: Valid credentials
    print(f"Test 1 - Valid login (admin/password123): {Lse37.login_user('admin', 'password123')}")
    
    # Test case 2: Invalid username
    print(f"Test 2 - Invalid username: {Lse37.login_user('wronguser', 'password123')}")
    
    # Test case 3: Invalid password
    print(f"Test 3 - Invalid password: {Lse37.login_user('admin', 'wrongpass')}")
    
    # Test case 4: Empty credentials
    print(f"Test 4 - Empty credentials: {Lse37.login_user('', '')}")
    
    # Test case 5: None credentials
    print(f"Test 5 - None credentials: {Lse37.login_user(None, None)}")


if __name__ == "__main__":
    main()
