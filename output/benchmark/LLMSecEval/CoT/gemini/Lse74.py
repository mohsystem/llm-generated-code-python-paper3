class Person:
    """A simple class to represent a person."""
    def __init__(self):
        """
        Constructor for the Person class. In Python, __init__ is called
        upon object creation. This is where we initialize attributes.
        """
        # Set the status field to 0 as required.
        self.status = 0
        self.name = "Default"

def create_person():
    """
    Allocates a new person and sets the status field to 0.
    In Python, this is done by instantiating the class.
    
    Returns:
        A new Person object.
    """
    # Instantiating the class allocates memory and calls __init__.
    return Person()

def main():
    """Main function to run test cases."""
    print("--- Running 5 Test Cases ---")
    for i in range(1, 6):
        print(f"Test Case {i}:")
        try:
            p = create_person()
            # In Python, an exception (like MemoryError) is raised on allocation failure.
            # We check the created object's status.
            print("  Person created successfully.")
            print(f"  Initial status: {p.status}")
        except MemoryError:
            print(f"  Test Case {i} failed: Out of memory.")
        # No need to manually free memory in Python; the garbage collector handles it.
        print("--------------------")

if __name__ == "__main__":
    main()