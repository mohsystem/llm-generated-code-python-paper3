import pickle

class UserData:
    def __init__(self, user_id, name):
        self.user_id = user_id
        self.name = name

    def __repr__(self):
        return f"UserData(user_id={self.user_id}, name='{self.name}')"

def serialize_data(user_object):
    """Serializes a Python object using pickle."""
    return pickle.dumps(user_object)

def deserialize_data(user_supplied_data):
    """
    Deserializes user-supplied data using pickle.
    
    Args:
        user_supplied_data: A bytes object representing the pickled data.
        
    Returns:
        The deserialized Python object, or None if an error occurs.
    """
    if not isinstance(user_supplied_data, bytes):
        print("Error: Input data must be bytes.")
        return None
    try:
        return pickle.loads(user_supplied_data)
    except (pickle.UnpicklingError, TypeError, EOFError) as e:
        print(f"Deserialization failed: {e}")
        return None

def main():
    """Main function with test cases."""
    print("--- Python Deserialization Test ---")
    
    # Test Cases
    test_cases = [
        UserData(101, "Alice"),
        UserData(102, "Bob"),
        UserData(103, "Charlie"),
        UserData(104, "David"),
        UserData(105, "Eve")
    ]
    
    for i, original_user in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Original Object: {original_user}")
        
        # 1. Serialize the object
        serialized_data = serialize_data(original_user)
        print(f"Serialized Data (bytes): {serialized_data}")
        
        # 2. Deserialize the data
        deserialized_user = deserialize_data(serialized_data)
        
        if deserialized_user:
            print(f"Deserialized Object: {deserialized_user}")
            # Verification
            assert original_user.user_id == deserialized_user.user_id
            assert original_user.name == deserialized_user.name
        else:
            print("Deserialization resulted in None.")

if __name__ == "__main__":
    main()