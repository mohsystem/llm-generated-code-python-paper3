
import sys
from typing import Optional

class Person:
    """Person class with validated fields"""
    
    def __init__(self, name: str = "", age: int = 0, address: str = ""):
        # Input validation with length and range checks
        if not isinstance(name, str) or len(name) > 100:
            raise ValueError("Invalid name: must be string with max 100 chars")
        if not isinstance(age, int) or age < 0 or age > 150:
            raise ValueError("Invalid age: must be between 0 and 150")
        if not isinstance(address, str) or len(address) > 200:
            raise ValueError("Invalid address: must be string with max 200 chars")
        
        self._name = name
        self._age = age
        self._address = address
    
    @property
    def name(self) -> str:
        return self._name
    
    @name.setter
    def name(self, value: str):
        if not isinstance(value, str) or len(value) > 100:
            raise ValueError("Invalid name")
        self._name = value
    
    @property
    def age(self) -> int:
        return self._age
    
    @age.setter
    def age(self, value: int):
        if not isinstance(value, int) or value < 0 or value > 150:
            raise ValueError("Invalid age")
        self._age = value
    
    @property
    def address(self) -> str:
        return self._address
    
    @address.setter
    def address(self, value: str):
        if not isinstance(value, str) or len(value) > 200:
            raise ValueError("Invalid address")
        self._address = value


def allocate_person(name: str = "", age: int = 0, address: str = "") -> Person:
    """\n    Allocates memory for a Person object and returns a pointer (reference) to it.\n    \n    In Python, memory allocation is handled automatically by the interpreter.\n    This function creates a new Person object and returns a reference to it.\n    \n    Args:\n        name: Person's name (max 100 chars)\n        age: Person's age (0-150)\n        address: Person's address (max 200 chars)\n    \n    Returns:\n        Person: A newly allocated Person object\n    \n    Raises:\n        ValueError: If input validation fails\n        MemoryError: If allocation fails\n    """
    # Validate inputs before allocation
    if not isinstance(name, str) or len(name) > 100:
        raise ValueError("Invalid name parameter")
    if not isinstance(age, int) or age < 0 or age > 150:
        raise ValueError("Invalid age parameter")
    if not isinstance(address, str) or len(address) > 200:
        raise ValueError("Invalid address parameter")
    
    try:
        # Allocate new Person object - Python handles memory automatically
        person = Person(name, age, address)
        return person
    except MemoryError as e:
        # Handle allocation failure
        raise MemoryError(f"Failed to allocate memory for Person: {e}")


def main():
    # Test case 1: Basic allocation with defaults
    print("Test 1: Basic allocation with defaults")
    try:
        p1 = allocate_person()
        print(f"Person allocated: Success - Name: '{p1.name}', Age: {p1.age}, Address: '{p1.address}'")
    except Exception as e:
        print(f"Failed: {e}")
    
    # Test case 2: Allocation with initialization
    print("\\nTest 2: Allocation with initialization")
    try:
        p2 = allocate_person("John Doe", 30, "123 Main St")
        print(f"Name: {p2.name}, Age: {p2.age}, Address: {p2.address}")
    except Exception as e:
        print(f"Failed: {e}")
    
    # Test case 3: Multiple allocations
    print("\\nTest 3: Multiple allocations")
    try:
        p3 = allocate_person("Alice Smith", 25, "456 Oak Ave")
        p4 = allocate_person("Bob Johnson", 45, "789 Pine Rd")
        print(f"p3 - Name: {p3.name}, Age: {p3.age}")
        print(f"p4 - Name: {p4.name}, Age: {p4.age}")
    except Exception as e:
        print(f"Failed: {e}")
    
    # Test case 4: Invalid input handling - type error
    print("\\nTest 4: Invalid input handling")
    try:
        p5 = allocate_person(None, 30, "Address")
        print("Should not reach here")
    except (ValueError, TypeError) as e:
        print(f"Caught expected exception: {e}")
    
    # Test case 5: Boundary value testing - negative age
    print("\\nTest 5: Boundary value testing")
    try:
        p6 = allocate_person("Valid Name", -5, "Address")
        print("Should not reach here")
    except ValueError as e:
        print(f"Caught expected exception for invalid age: {e}")
    
    # Test boundary with valid minimum age
    try:
        p7 = allocate_person("Edge Case", 0, "Valid Address")
        print(f"Allocated person with age 0: Success")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
