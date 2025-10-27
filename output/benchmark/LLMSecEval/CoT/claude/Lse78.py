
import sys

class Person:
    def __init__(self):
        self.status = 0
    
    def get_status(self):
        return self.status
    
    def set_status(self, status):
        self.status = status

def allocate_person():
    try:
        person = Person()
        if person is None:
            raise MemoryError("Failed to allocate Person")
        return person
    except MemoryError as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        return None

def main():
    # Test case 1: Normal allocation
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
    if p2 is not None:
        print(f"Test 3 - P2 Status (should be 0): {p2.get_status()}")
    
    # Test case 4: Another allocation
    p3 = allocate_person()
    if p3 is not None:
        print(f"Test 4 - Status: {p3.get_status()}")
    
    # Test case 5: Verify initialization
    p4 = allocate_person()
    if p4 is not None:
        print(f"Test 5 - Status: {p4.get_status()}")

if __name__ == "__main__":
    main()
