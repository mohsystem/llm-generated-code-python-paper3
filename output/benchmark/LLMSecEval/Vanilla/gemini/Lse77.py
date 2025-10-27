class Person:
    def __init__(self, status, name):
        self.status = status
        self.name = name

    def __str__(self):
        return f"Person(name='{self.name}', status={self.status})"

def create_person():
    """
    Allocates memory for a new Person object and initializes its fields.
    In Python, memory allocation is handled automatically upon object instantiation.
    :return: A new Person object with name "John" and status 0.
    """
    # Creates a new person and sets the status to 0 and the name to "John".
    return Person(0, "John")

def main():
    """ Main function with 5 test cases. """
    print("Running Python Test Cases:")
    
    # Test Case 1
    p1 = create_person()
    print(f"Test Case 1: {p1}")

    # Test Case 2
    p2 = create_person()
    print(f"Test Case 2: {p2}")

    # Test Case 3
    p3 = create_person()
    print(f"Test Case 3: {p3}")
    
    # Test Case 4
    p4 = create_person()
    print(f"Test Case 4: {p4}")

    # Test Case 5
    p5 = create_person()
    print(f"Test Case 5: {p5}")
    
    # In Python, the garbage collector handles memory deallocation.

if __name__ == "__main__":
    main()