class Person:
    """A simple class to represent a person."""
    def __init__(self):
        # The status is set to 0 upon creation (memory allocation)
        self.status = 0

def allocate_person():
    """
    Allocates a new person and sets the status to 0.
    In Python, this is done by instantiating the class.
    """
    return Person()

if __name__ == "__main__":
    print("--- Python Test Cases ---")
    
    # Test Case 1
    p1 = allocate_person()
    print(f"Test Case 1: Person allocated with status: {p1.status}")

    # Test Case 2
    p2 = allocate_person()
    print(f"Test Case 2: Person allocated with status: {p2.status}")

    # Test Case 3
    p3 = allocate_person()
    print(f"Test Case 3: Person allocated with status: {p3.status}")

    # Test Case 4
    p4 = allocate_person()
    print(f"Test Case 4: Person allocated with status: {p4.status}")

    # Test Case 5
    p5 = allocate_person()
    print(f"Test Case 5: Person allocated with status: {p5.status}")