
import sys
from typing import Optional

class Person:
    def __init__(self):
        # Initialize status to 0
        self.status: int = 0

def allocate_person() -> Optional[Person]:
    """\n    Allocates a new Person object with status initialized to 0.\n    Returns None on allocation failure.\n    """
    try:
        # Allocate new Person object
        person = Person()
        # Explicit initialization to 0 (already done in __init__)
        person.status = 0
        return person
    except MemoryError:
        # Return None on allocation failure
        return None

def main():
    # Test case 1: Normal allocation
    p1 = allocate_person()
    if p1 is not None:
        print(f"Test 1 - Person allocated, status: {p1.status}")
    else:
        print("Test 1 - Allocation failed")
    
    # Test case 2: Verify status is 0
    p2 = allocate_person()
    if p2 is not None:
        print(f"Test 2 - Status is zero: {p2.status == 0}")
    
    # Test case 3: Multiple allocations
    p3 = allocate_person()
    if p3 is not None:
        print(f"Test 3 - Multiple allocations work, status: {p3.status}")
    
    # Test case 4: Verify independence of objects
    p4 = allocate_person()
    p5 = allocate_person()
    if p4 is not None and p5 is not None:
        p4.status = 1
        print(f"Test 4 - Objects are independent: {p5.status == 0}")
    
    # Test case 5: Null check handling
    p6 = allocate_person()
    print(f"Test 5 - None check passed: {p6 is not None}")

if __name__ == "__main__":
    main()
