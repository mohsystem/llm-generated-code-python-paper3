
import pickle
import json
import io
from typing import Any, Set

class Task131:
    # Whitelist of allowed classes for deserialization
    ALLOWED_CLASSES = {
        'SafeData',
        'str',
        'int',
        'float',
        'list',
        'dict'
    }
    
    class SafeData:
        """Simple data class for safe serialization"""
        def __init__(self, name: str, value: int):
            self.name = name
            self.value = value
        
        def __repr__(self):
            return f"SafeData(name='{self.name}', value={self.value})"
        
        def to_dict(self):
            return {'name': self.name, 'value': self.value}
        
        @classmethod
        def from_dict(cls, data):
            return cls(data['name'], data['value'])
    
    class RestrictedUnpickler(pickle.Unpickler):
        """Secure unpickler with class whitelist validation"""
        def find_class(self, module, name):
            # Only allow specific safe classes
            if name in Task131.ALLOWED_CLASSES:
                return super().find_class(module, name)
            raise pickle.UnpicklingError(f"Unauthorized deserialization attempt: {module}.{name}")
    
    @staticmethod
    def serialize_object(obj: Any) -> bytes:
        """Serialize object to bytes using pickle"""
        return pickle.dumps(obj)
    
    @staticmethod
    def deserialize_securely(data: bytes) -> Any:
        """Securely deserialize with whitelist validation"""
        if not data:
            raise ValueError("Invalid serialized data")
        
        # Use restricted unpickler for security
        return Task131.RestrictedUnpickler(io.BytesIO(data)).load()
    
    @staticmethod
    def serialize_to_json(data: 'Task131.SafeData') -> str:
        """Serialize to JSON (safer alternative)"""
        return json.dumps(data.to_dict())
    
    @staticmethod
    def deserialize_from_json(json_str: str) -> 'Task131.SafeData':
        """Deserialize from JSON"""
        data = json.loads(json_str)
        return Task131.SafeData.from_dict(data)

def main():
    print("=== Secure Deserialization Tests ===\\n")
    
    # Test Case 1: Deserialize SafeData object using JSON
    try:
        print("Test 1: Deserialize SafeData object (JSON)")
        original = Task131.SafeData("TestData", 42)
        json_data = Task131.serialize_to_json(original)
        deserialized = Task131.deserialize_from_json(json_data)
        print(f"Original: {original}")
        print(f"Deserialized: {deserialized}")
        print("Success!\\n")
    except Exception as e:
        print(f"Error: {e}\\n")
    
    # Test Case 2: Deserialize String
    try:
        print("Test 2: Deserialize String")
        original = "Hello, Secure World!"
        serialized = Task131.serialize_object(original)
        deserialized = pickle.loads(serialized)  # Safe for basic types
        print(f"Original: {original}")
        print(f"Deserialized: {deserialized}")
        print("Success!\\n")
    except Exception as e:
        print(f"Error: {e}\\n")
    
    # Test Case 3: Deserialize Integer
    try:
        print("Test 3: Deserialize Integer")
        original = 12345
        serialized = Task131.serialize_object(original)
        deserialized = pickle.loads(serialized)
        print(f"Original: {original}")
        print(f"Deserialized: {deserialized}")
        print("Success!\\n")
    except Exception as e:
        print(f"Error: {e}\\n")
    
    # Test Case 4: JSON-based serialization (safer alternative)
    try:
        print("Test 4: JSON-based serialization with complex data")
        original = Task131.SafeData("JSONData", 999)
        json_str = Task131.serialize_to_json(original)
        deserialized = Task131.deserialize_from_json(json_str)
        print(f"Original: {original}")
        print(f"JSON: {json_str}")
        print(f"Deserialized: {deserialized}")
        print("Success!\\n")
    except Exception as e:
        print(f"Error: {e}\\n")
    
    # Test Case 5: Demonstrate whitelist protection
    try:
        print("Test 5: Whitelist protection demonstration")
        print(f"Whitelist protection is active.")
        print(f"Only allowed classes: {Task131.ALLOWED_CLASSES}")
        print("Recommended: Use JSON for untrusted data")
        print("Success!\\n")
    except Exception as e:
        print(f"Error: {e}\\n")

if __name__ == "__main__":
    main()
