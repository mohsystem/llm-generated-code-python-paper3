
import sys
from typing import Optional

class Person:
    """Person class with validated memory allocation"""
    
    def __init__(self, status: int, name: str):
        # Input validation: check types
        if not isinstance(status, int):
            raise TypeError("Status must be an integer")
        if not isinstance(name, str):
            raise TypeError("Name must be a string")
        
        # Validate status range
        if status < 0 or status > 1000:
            raise ValueError("Status must be between 0 and 1000")
        
        # Validate name length to prevent excessive memory usage
        if len(name) > 255:
            raise ValueError("Name exceeds maximum length of 255 characters")
        
        # Sanitize name - remove control characters
        self._name = ''.join(char for char in name if not char.isspace() or char == ' ')
        self._status = status
    
    @property
    def status(self) -> int:
        return self._status
    
    @property
    def name(self) -> str:
        return self._name
    
    def clear(self):
        """Clear sensitive data"""
        self._status = 0
        self._name = ""


def create_person(status: int, name: str) -> Person:
    """\n    Factory function to create a Person object with validated inputs.\n    \n    Args:\n        status: Integer status value (0-1000)\n        name: String name (max 255 chars)\n    \n    Returns:\n        Person: Newly allocated Person object\n    \n    Raises:\n        ValueError: If inputs are invalid\n        TypeError: If inputs have wrong type\n    """
    # Input validation happens in Person.__init__
    # This function serves as the public API
    return Person(status, name)


def main():
    """Test cases for Person creation"""
    
    # Test case 1: Create person with status 0 and name "John"
    try:
        person1 = create_person(0, "John")
        print(f"Test 1 - Status: {person1.status}, Name: {person1.name}")
        person1.clear()
    except Exception as e:
        print(f"Test 1 failed: {e}", file=sys.stderr)
    
    # Test case 2: Create person with different status
    try:
        person2 = create_person(1, "Alice")
        print(f"Test 2 - Status: {person2.status}, Name: {person2.name}")
        person2.clear()
    except Exception as e:
        print(f"Test 2 failed: {e}", file=sys.stderr)
    
    # Test case 3: Create person with empty name
    try:
        person3 = create_person(0, "")
        print(f"Test 3 - Status: {person3.status}, Name: '{person3.name}'")
        person3.clear()
    except Exception as e:
        print(f"Test 3 failed: {e}", file=sys.stderr)
    
    # Test case 4: Attempt to create with invalid status (should fail)
    try:
        person4 = create_person(-1, "Bob")
        print(f"Test 4 - Status: {person4.status}, Name: {person4.name}")
    except Exception as e:
        print(f"Test 4 correctly rejected invalid status: {e}")
    
    # Test case 5: Attempt to create with oversized name (should fail)
    try:
        person5 = create_person(0, "X" * 256)
        print(f"Test 5 - Status: {person5.status}, Name length: {len(person5.name)}")
    except Exception as e:
        print(f"Test 5 correctly rejected oversized name: {e}")


if __name__ == "__main__":
    main()
