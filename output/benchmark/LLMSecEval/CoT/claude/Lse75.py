
import sys
from ctypes import Structure, c_int, pointer, sizeof, cast, POINTER, c_char

class Person(Structure):
    _fields_ = [("status", c_int)]

def allocate_person():
    """\n    Allocates memory for a Person structure and initializes status to 0\n    Returns: Person object or None on failure\n    """
    try:
        person = Person()
        person.status = 0
        return person
    except MemoryError as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return None

def main():
    # Test case 1: Normal allocation
    p1 = allocate_person()
    if p1 is not None:
        print(f"Test 1 - Status: {p1.status}")
    
    # Test case 2: Multiple allocations
    p2 = allocate_person()
    if p2 is not None:
        print(f"Test 2 - Status: {p2.status}")
    
    # Test case 3: Verify independent objects
    p3 = allocate_person()
    if p3 is not None:
        p3.status = 5
        print(f"Test 3 - Modified status: {p3.status}")
    
    # Test case 4: Check original unchanged
    if p1 is not None:
        print(f"Test 4 - Original status: {p1.status}")
    
    # Test case 5: Multiple allocations in loop
    print("Test 5 - Allocating 5 persons:")
    for i in range(5):
        p = allocate_person()
        if p is not None:
            print(f"  Person {i+1} status: {p.status}")

if __name__ == "__main__":
    main()
