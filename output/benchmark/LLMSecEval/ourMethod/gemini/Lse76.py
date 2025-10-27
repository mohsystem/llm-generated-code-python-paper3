import sys

class Person:
    """A simple class to represent a person."""
    
    def __init__(self):
        """
        Constructor for the Person class.
        Initializes the status to 0 upon object creation.
        """
        self.status = 0

    def __repr__(self):
        """Provide a developer-friendly representation of the object."""
        return f"Person(status={self.status})"

def allocate_person():
    """
    Allocates a new Person object and sets its status to 0.
    In Python, this is done by instantiating the class. The __init__
    method handles the initialization.
    
    Returns:
        A new Person object, or None if a MemoryError occurs.
    """
    try:
        # Instantiation allocates memory for the object.
        return Person()
    except MemoryError:
        # Return None to indicate allocation failure.
        return None

def main():
    """Main function to run test cases."""
    print("--- Running Python Test Cases ---")
    
    # Test cases: Allocate 5 Person objects
    for i in range(1, 6):
        print(f"Test Case #{i}")
        p = allocate_person()
        
        if p is not None:
            print(f"  Allocation successful: {p}")
            print(f"  Status is correctly set to: {p.status}")
            # Memory is managed by the garbage collector in Python.
            # No manual deallocation is necessary.
        else:
            print("  Memory allocation failed.", file=sys.stderr)
            # In a real application, handle the failure appropriately.
        print()

if __name__ == "__main__":
    main()