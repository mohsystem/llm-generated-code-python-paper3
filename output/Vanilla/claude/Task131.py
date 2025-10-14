
import pickle
import io

def deserialize_from_bytes(data):
    """Deserialize from byte array"""
    return pickle.loads(data)

def deserialize_from_file(filename):
    """Deserialize from file"""
    with open(filename, 'rb') as f:
        return pickle.load(f)

def serialize_to_bytes(obj):
    """Helper method to serialize an object (for testing)"""
    return pickle.dumps(obj)

if __name__ == "__main__":
    # Test Case 1: Serialize and deserialize a String
    print("Test Case 1: String")
    str1 = "Hello, World!"
    serialized1 = serialize_to_bytes(str1)
    deserialized1 = deserialize_from_bytes(serialized1)
    print(f"Original: {str1}")
    print(f"Deserialized: {deserialized1}")
    print()
    
    # Test Case 2: Serialize and deserialize an Integer
    print("Test Case 2: Integer")
    num = 42
    serialized2 = serialize_to_bytes(num)
    deserialized2 = deserialize_from_bytes(serialized2)
    print(f"Original: {num}")
    print(f"Deserialized: {deserialized2}")
    print()
    
    # Test Case 3: Serialize and deserialize a List
    print("Test Case 3: List")
    lst = ["Apple", "Banana", "Cherry"]
    serialized3 = serialize_to_bytes(lst)
    deserialized3 = deserialize_from_bytes(serialized3)
    print(f"Original: {lst}")
    print(f"Deserialized: {deserialized3}")
    print()
    
    # Test Case 4: Serialize and deserialize a Dictionary
    print("Test Case 4: Dictionary")
    dct = {"One": 1, "Two": 2, "Three": 3}
    serialized4 = serialize_to_bytes(dct)
    deserialized4 = deserialize_from_bytes(serialized4)
    print(f"Original: {dct}")
    print(f"Deserialized: {deserialized4}")
    print()
    
    # Test Case 5: Serialize and deserialize a Tuple
    print("Test Case 5: Tuple")
    tpl = (1.1, 2.2, 3.3, 4.4, 5.5)
    serialized5 = serialize_to_bytes(tpl)
    deserialized5 = deserialize_from_bytes(serialized5)
    print(f"Original: {tpl}")
    print(f"Deserialized: {deserialized5}")
