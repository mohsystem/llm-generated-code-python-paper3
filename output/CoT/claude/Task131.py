
import json
import re
from typing import Dict, Any

class UserData:
    def __init__(self, name: str, age: int, email: str):
        self.name = name
        self.age = age
        self.email = email
    
    def __str__(self):
        return f"UserData(name='{self.name}', age={self.age}, email='{self.email}')"

def deserialize_user_data(json_data: str) -> UserData:
    """\n    Securely deserialize user-supplied JSON data.\n    Uses JSON instead of pickle to prevent arbitrary code execution.\n    """
    if not json_data or not json_data.strip():
        raise ValueError("Input data cannot be null or empty")
    
    try:
        # Parse JSON safely
        data = json.loads(json_data)
        
        # Validate required fields exist
        if not isinstance(data, dict):
            raise ValueError("Input must be a JSON object")
        
        if 'name' not in data or 'age' not in data or 'email' not in data:
            raise ValueError("Missing required fields: name, age, email")
        
        name = data['name']
        age = data['age']
        email = data['email']
        
        # Validate data types and values
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Name must be a non-empty string")
        
        if not isinstance(age, int) or age < 0 or age > 150:
            raise ValueError("Age must be an integer between 0 and 150")
        
        if not isinstance(email, str) or not re.match(r'^[A-Za-z0-9+_.-]+@(.+)$', email):
            raise ValueError("Invalid email format")
        
        return UserData(name, age, email)
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")

def main():
    print("=== Secure Deserialization Test Cases ===\\n")
    
    # Test Case 1: Valid data
    try:
        json1 = '{"name":"John Doe","age":30,"email":"john@example.com"}'
        user1 = deserialize_user_data(json1)
        print(f"Test 1 - Valid data: {user1}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test Case 2: Valid data with different values
    try:
        json2 = '{"name":"Jane Smith","age":25,"email":"jane@test.com"}'
        user2 = deserialize_user_data(json2)
        print(f"Test 2 - Valid data: {user2}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test Case 3: Invalid age (negative)
    try:
        json3 = '{"name":"Bob","age":-5,"email":"bob@example.com"}'
        user3 = deserialize_user_data(json3)
        print(f"Test 3 - Should fail: {user3}")
    except Exception as e:
        print(f"Test 3 - Expected failure: {e}")
    
    # Test Case 4: Invalid email format
    try:
        json4 = '{"name":"Alice","age":28,"email":"invalid-email"}'
        user4 = deserialize_user_data(json4)
        print(f"Test 4 - Should fail: {user4}")
    except Exception as e:
        print(f"Test 4 - Expected failure: {e}")
    
    # Test Case 5: Invalid JSON syntax
    try:
        json5 = '{"name":"Charlie","age":35,"email":"charlie@test.com"'
        user5 = deserialize_user_data(json5)
        print(f"Test 5 - Should fail: {user5}")
    except Exception as e:
        print(f"Test 5 - Expected failure: {e}")

if __name__ == "__main__":
    main()
