
import sys
from typing import Optional

class Person:
    """Person class with status field"""
    def __init__(self):
        # Initialize status to 0 as required
        self.status: int = 0
    
    def get_status(self) -> int:
        return self.status
    
    def set_status(self, status: int) -> None:
        self.status = status


def allocate_person() -> Optional[Person]:
    """\n    Memory allocation method that creates a new Person and sets status to 0.\n    Returns the newly allocated Person object or None on failure.\n    """
    try:
        # Allocate new Person object (Python handles memory allocation automatically)
        new_person = Person()
        # Status is already initialized to 0 in __init__
        return new_person
    except MemoryError:
        # Handle memory allocation failure gracefully
        print("Error: Failed to allocate memory for Person", file=sys.stderr)
        return None


def main():
    # Test case 1: Basic allocation
    p1 = allocate_person()
    if p1 is not None:
        print(f"Test 1 - Status: {p1.get_status()}")
    
    # Test case 2: Multiple allocations
    p2 = allocate_person()
    if p2 is not None:
        print(f"Test 2 - Status: {p2.get_status()}")
    
    # Test case 3: Verify independence
    if p1 is not None:
        p1.set_status(5)
        p3 = allocate_person()
        if p3 is not None:
            print(f"Test 3 - p1 Status: {p1.get_status()}, p3 Status: {p3.get_status()}")
    
    # Test case 4: Array of persons
    persons = []
    for i in range(3):
        p = allocate_person()
        if p is not None:
            persons.append(p)
            print(f"Test 4.{i+1} - Status: {p.get_status()}")
    
    # Test case 5: Null safety check
    p5 = allocate_person()
    if p5 is not None:
        print(f"Test 5 - Allocation successful, Status: {p5.get_status()}")


if __name__ == "__main__":
    main()
