
import sqlite3
import re
from typing import Dict, Tuple

class Task49:
    DB_NAME = "users.db"
    EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    
    @staticmethod
    def init_database():
        """Initialize the database with users table"""
        try:
            conn = sqlite3.connect(Task49.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    name TEXT NOT NULL,\n                    email TEXT NOT NULL UNIQUE,\n                    age INTEGER NOT NULL\n                )\n            """)
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def validate_input(name: str, email: str, age: int) -> bool:
        """Validate user input data"""
        if not name or not name.strip() or len(name) > 100:
            return False
        if not email or not Task49.EMAIL_PATTERN.match(email):
            return False
        if not isinstance(age, int) or age < 0 or age > 150:
            return False
        return True
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input string"""
        if input_str is None:
            return ""
        return re.sub(r'[<>"\';\\0]', '', input_str.strip())
    
    @staticmethod
    def store_user_data(name: str, email: str, age: int) -> Dict[str, any]:
        """Store user data in database securely"""
        name = Task49.sanitize_input(name)
        email = Task49.sanitize_input(email)
        
        if not Task49.validate_input(name, email, age):
            return {"success": False, "message": "Invalid input data"}
        
        try:
            conn = sqlite3.connect(Task49.DB_NAME)
            cursor = conn.cursor()
            
            # Using parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO users (name, email, age) VALUES (?, ?, ?)",
                (name, email, age)
            )
            
            conn.commit()
            conn.close()
            
            return {"success": True, "message": "User data stored successfully"}
            
        except sqlite3.IntegrityError:
            return {"success": False, "message": "Email already exists"}
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {str(e)}"}

if __name__ == "__main__":
    Task49.init_database()
    
    print("=== API Endpoint Test Cases ===\\n")
    
    # Test Case 1: Valid user data
    print("Test 1 - Valid user:")
    response1 = Task49.store_user_data("John Doe", "john@example.com", 25)
    print(f"Success: {response1['success']}, Message: {response1['message']}\\n")
    
    # Test Case 2: Another valid user
    print("Test 2 - Another valid user:")
    response2 = Task49.store_user_data("Jane Smith", "jane@example.com", 30)
    print(f"Success: {response2['success']}, Message: {response2['message']}\\n")
    
    # Test Case 3: Duplicate email
    print("Test 3 - Duplicate email:")
    response3 = Task49.store_user_data("John Clone", "john@example.com", 35)
    print(f"Success: {response3['success']}, Message: {response3['message']}\\n")
    
    # Test Case 4: Invalid email format
    print("Test 4 - Invalid email:")
    response4 = Task49.store_user_data("Invalid User", "notanemail", 28)
    print(f"Success: {response4['success']}, Message: {response4['message']}\\n")
    
    # Test Case 5: Invalid age
    print("Test 5 - Invalid age:")
    response5 = Task49.store_user_data("Old Person", "old@example.com", 200)
    print(f"Success: {response5['success']}, Message: {response5['message']}\\n")
