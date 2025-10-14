import json

class UserData:
    """
    A simple data class to hold user information. It has no methods,
    making it a safe target for deserialization.
    """
    def __init__(self, user_id=0, name=None, is_admin=False):
        self.user_id = user_id
        self.name = name
        self.is_admin = is_admin

    def __repr__(self):
        return f"UserData(user_id={self.user_id}, name='{self.name}', is_admin={self.is_admin})"

def deserialize_user_data(json_string):
    """
    Securely deserializes a JSON string into a UserData object.

    SECURITY NOTE: This function is secure because it uses Python's built-in `json`
    library, which only parses data and does not execute any code. It deliberately avoids
    the dangerous `pickle` module, which can be exploited to run arbitrary commands
    if processing untrusted data.

    Args:
        json_string: The user-supplied JSON string.

    Returns:
        A UserData object if deserialization is successful, None otherwise.
    """
    if not isinstance(json_string, str) or not json_string.strip():
        print("Error: Input is not a valid string or is empty.")
        return None
    try:
        # json.loads() safely parses a JSON string into a Python dictionary.
        data = json.loads(json_string)
        
        # We explicitly map the dictionary data to our class, which prevents
        # unexpected attributes from being set.
        return UserData(
            user_id=data.get('id', 0),
            name=data.get('name'),
            is_admin=data.get('isAdmin', False)
        )
    except json.JSONDecodeError as e:
        # Catching parsing errors prevents crashes on malformed input.
        print(f"Error deserializing JSON: {e}")
        return None
    except TypeError:
        # Catches cases where json_string is not a string, e.g., if it's already a dict.
        print("Error: Invalid input type for deserialization.")
        return None

def main():
    # --- Test Cases ---
    test_cases = [
        # Test Case 1: Valid JSON
        '{"id": 201, "name": "Eve", "isAdmin": false}',
        # Test Case 2: JSON with extra, unknown fields (safely ignored by .get())
        '{"id": 202, "name": "Frank", "isAdmin": true, "role": "user"}',
        # Test Case 3: Malformed JSON (invalid syntax)
        '{"id": 203, "name": "Grace", "isAdmin": false,}',
        # Test Case 4: JSON with missing fields (default values will be used)
        '{"id": 204, "name": "Heidi"}',
        # Test Case 5: Empty string input
        ''
    ]
    
    print("--- Running Python Test Cases ---")
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Input: {test_case}")
        user = deserialize_user_data(test_case)
        if user:
            print(f"Deserialized successfully: {user}")
        else:
            print("Deserialization failed.")

if __name__ == "__main__":
    main()