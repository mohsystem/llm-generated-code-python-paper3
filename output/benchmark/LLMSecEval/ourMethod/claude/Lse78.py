
# Python: Memory is managed automatically via reference counting and GC
# We create a Person class and initialize status to 0

class Person:
    """Person class with status attribute initialized to 0"""
    
    def __init__(self):
        # Initialize status to 0 (secure default state)
        self.status = 0
    
    def __repr__(self):
        return f"Person(status={self.status})"


def allocate_person():
    """\n    Allocates a new Person object with status set to 0.\n    Python handles memory allocation automatically.\n    Returns a reference to the new Person object.\n    """
    # Python automatically allocates memory for new objects
    # Memory is freed when reference count reaches zero
    new_person = Person()
    return new_person


def main():
    # Test case 1: Basic allocation
    p1 = allocate_person()
    print(f"Test 1: {p1}")
    
    # Test case 2: Multiple allocations
    p2 = allocate_person()
    p3 = allocate_person()
    print(f"Test 2: {p2}, {p3}")
    
    # Test case 3: Verify initial status
    p4 = allocate_person()
    print(f"Test 3: Status is {p4.status}")
    
    # Test case 4: Modify status after allocation
    p5 = allocate_person()
    p5.status = 1
    print(f"Test 4: Modified status to {p5.status}")
    
    # Test case 5: List of persons
    people = [allocate_person() for _ in range(3)]
    print(f"Test 5: Allocated {len(people)} persons")
    for i, person in enumerate(people):
        print(f"  Person {i}: {person}")


if __name__ == "__main__":
    main()
