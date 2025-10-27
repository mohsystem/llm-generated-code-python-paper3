
import sys

class Person:
    def __init__(self):
        self.status = 0
        self.name = ""
        self.age = 0

def allocate_person():
    try:
        person = Person()
        person.status = 0
        return person
    except MemoryError as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        return None

def main():
    # Test case 1: Normal allocation
    p1 = allocate_person()
    if p1 is not None:
        print(f"Test 1 - Person allocated, status: {p1.status}")
    
    # Test case 2: Verify status is 0
    p2 = allocate_person()
    if p2 is not None:
        print(f"Test 2 - Status is zero: {p2.status == 0}")
    
    # Test case 3: Multiple allocations
    p3 = allocate_person()
    if p3 is not None:
        print(f"Test 3 - Multiple allocation successful, status: {p3.status}")
    
    # Test case 4: Modify and verify independence
    p4 = allocate_person()
    if p4 is not None:
        p4.status = 5
        print(f"Test 4 - Modified status: {p4.status}")
    
    # Test case 5: Verify new allocation is still 0
    p5 = allocate_person()
    if p5 is not None:
        print(f"Test 5 - New allocation status still 0: {p5.status == 0}")

if __name__ == "__main__":
    main()
