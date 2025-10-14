import json
from dataclasses import dataclass
from typing import Dict, Any, Union

# Using a dataclass for a simple, typed data structure.
@dataclass
class UserData:
    id: int
    name: str

def serialize(user: UserData) -> str:
    """
    Serializes a UserData object into a JSON string.
    """
    if not isinstance(user, UserData):
        raise TypeError("Input must be a UserData object.")
    return json.dumps({"id": user.id, "name": user.name})

def deserialize(data: str) -> UserData:
    """
    Deserializes a JSON string into a UserData object.
    Uses the safe 'json' module, which only parses data and does not
    execute any code, avoiding insecure deserialization vulnerabilities.
    
    Args:
        data: The JSON string to deserialize.
        
    Returns:
        A new UserData object.
        
    Raises:
        ValueError: if the data format is invalid, missing keys, or has wrong types.
    """
    if not isinstance(data, str) or not data.strip():
        raise ValueError("Input data must be a non-empty string.")

    MAX_NAME_LENGTH = 256

    try:
        parsed_obj: Dict[str, Any] = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON format.") from e

    if not isinstance(parsed_obj, dict):
        raise ValueError("Deserialized object is not a dictionary.")
    
    # Validate structure and types
    if 'id' not in parsed_obj or 'name' not in parsed_obj:
        raise ValueError("JSON object is missing 'id' or 'name' key.")
        
    user_id = parsed_obj['id']
    user_name = parsed_obj['name']

    if not isinstance(user_id, int):
        raise ValueError("Type mismatch: 'id' must be an integer.")
    if not isinstance(user_name, str):
        raise ValueError("Type mismatch: 'name' must be a string.")

    if not user_name:
        raise ValueError("Name cannot be empty.")
    if len(user_name) > MAX_NAME_LENGTH:
        raise ValueError(f"Name exceeds maximum length of {MAX_NAME_LENGTH}")

    return UserData(id=user_id, name=user_name)

def main():
    """Main function with test cases."""
    print("--- Python Deserialization Tests ---")
    
    # Test Case 1: Valid data
    user1 = UserData(id=101, name="Alice")
    serialized1 = serialize(user1)
    try:
        deserialized1 = deserialize(serialized1)
        assert user1 == deserialized1
        print(f"Test 1 (Valid): PASSED - {deserialized1}")
    except Exception as e:
        print(f"Test 1 (Valid): FAILED - {e}")

    # Test Case 2: Invalid JSON format
    serialized2 = '{"id": 102, "name": "Bob"'
    try:
        deserialize(serialized2)
        print("Test 2 (Invalid JSON): FAILED - No exception thrown")
    except ValueError as e:
        print(f"Test 2 (Invalid JSON): PASSED - {e}")

    # Test Case 3: Missing 'name' key
    serialized3 = '{"id": 103}'
    try:
        deserialize(serialized3)
        print("Test 3 (Missing Key): FAILED - No exception thrown")
    except ValueError as e:
        print(f"Test 3 (Missing Key): PASSED - {e}")

    # Test Case 4: Wrong type for 'id'
    serialized4 = '{"id": "104", "name": "Dave"}'
    try:
        deserialize(serialized4)
        print("Test 4 (Wrong Type): FAILED - No exception thrown")
    except ValueError as e:
        print(f"Test 4 (Wrong Type): PASSED - {e}")

    # Test Case 5: Empty string input
    serialized5 = ""
    try:
        deserialize(serialized5)
        print("Test 5 (Empty Input): FAILED - No exception thrown")
    except ValueError as e:
        print(f"Test 5 (Empty Input): PASSED - {e}")


if __name__ == "__main__":
    main()