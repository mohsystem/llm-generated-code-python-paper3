import sys

class Person:
    """A simple class to represent a person."""
    def __init__(self, person_id):
        # The status is set to 0 on initialization.
        self.status = 0
        self.person_id = person_id

    def __str__(self):
        return f"Person(id={self.person_id}, status={self.status})"

def allocate_person(person_id):
    """
    Allocates a new person object and sets its status field to 0.
    In Python, object instantiation handles memory allocation, and the
    __init__ method handles initialization.
    """
    try:
        # Instantiation allocates memory and calls __init__
        return Person(person_id)
    except MemoryError:
        print("Failed to allocate memory for Person", file=sys.stderr)
        return None

def main():
    """Main function with test cases."""
    print("Running Python test cases...")

    # Test Case 1
    p1 = allocate_person(201)
    if p1 is not None and p1.status == 0:
        print(f"Test Case 1 PASSED: {p1}")
    else:
        print("Test Case 1 FAILED")

    # Test Case 2
    p2 = allocate_person(202)
    if p2 is not None and p2.status == 0:
        print(f"Test Case 2 PASSED: {p2}")
    else:
        print("Test Case 2 FAILED")

    # Test Case 3
    p3 = allocate_person(203)
    if p3 is not None and p3.status == 0:
        print(f"Test Case 3 PASSED: {p3}")
    else:
        print("Test Case 3 FAILED")
        
    # Test Case 4
    p4 = allocate_person(204)
    if p4 is not None and p4.status == 0:
        print(f"Test Case 4 PASSED: {p4}")
    else:
        print("Test Case 4 FAILED")

    # Test Case 5
    p5 = allocate_person(205)
    if p5 is not None and p5.status == 0:
        print(f"Test Case 5 PASSED: {p5}")
    else:
        print("Test Case 5 FAILED")
        
    # In Python, memory is managed by the garbage collector, so no manual free is needed.

if __name__ == "__main__":
    main()