import json
import os

# SECURITY WARNING: The 'pickle' module is NOT secure against erroneous or
# maliciously constructed data. Never unpickle data received from an
# untrusted or unauthenticated source. The SECURE approach for user-supplied
# data is to use a data-only format like JSON.

class UserData:
    def __init__(self, name, user_id, is_active):
        self.name = name
        self.user_id = user_id
        self.is_active = is_active

    def to_dict(self):
        """Converts the object to a dictionary for safe serialization."""
        return {"name": self.name, "user_id": self.user_id, "is_active": self.is_active}

    @classmethod
    def from_dict(cls, data_dict):
        """Creates an object from a dictionary after safe deserialization."""
        return cls(data_dict['name'], data_dict['user_id'], data_dict['is_active'])

    def __eq__(self, other):
        if not isinstance(other, UserData):
            return NotImplemented
        return self.name == other.name and \
               self.user_id == other.user_id and \
               self.is_active == other.is_active

    def __repr__(self):
        return f"UserData(name='{self.name}', user_id={self.user_id}, is_active={self.is_active})"

def serialize_safely(user_obj):
    """
    Serializes a UserData object to a JSON string.
    This is secure because JSON only represents data, not executable code.
    """
    return json.dumps(user_obj.to_dict())

def deserialize_safely(json_string):
    """
    Deserializes a JSON string back into a UserData object.
    Includes basic validation to ensure all required keys are present.
    """
    try:
        data_dict = json.loads(json_string)
        # Validate that the dictionary contains the expected keys
        required_keys = ['name', 'user_id', 'is_active']
        if all(key in data_dict for key in required_keys):
            return UserData.from_dict(data_dict)
        else:
            print("Error: JSON data is missing required fields.")
            return None
    except (json.JSONDecodeError, TypeError):
        print("Error: Invalid or non-string JSON provided.")
        return None

def main():
    """Main function with test cases."""
    print("--- Python Secure Deserialization Demo (using JSON) ---")
    
    test_cases = [
        UserData("Alice", 101, True),
        UserData("Bob", 202, False),
        UserData("Charlie", 303, True),
        UserData("David", 404, False),
        UserData("", 0, False)
    ]

    for i, original_user in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Original:     {original_user!r}")
        
        json_data = serialize_safely(original_user)
        print(f"Serialized (JSON): {json_data}")
        
        deserialized_user = deserialize_safely(json_data)
        
        if deserialized_user:
            print(f"Deserialized: {deserialized_user!r}")
            print(f"Objects are equal: {original_user == deserialized_user}")
        else:
            print("Deserialization failed.")

    print("\n--- Security Test Case (Malformed Data) ---")
    malformed_json = '{"name": "Eve", "user_id": 999}' # Missing 'is_active'
    print(f"Attempting to deserialize malformed JSON: {malformed_json}")
    result = deserialize_safely(malformed_json)
    if result is None:
        print("SUCCESS: Malformed JSON was correctly handled and rejected.")
    else:
        print("FAILURE: Malformed JSON was not handled correctly.")


if __name__ == "__main__":
    main()