class Person:
    """A simple class to represent a person."""
    def __init__(self):
        """Constructor that initializes status to 0."""
        self.status = 0

def allocate_person():
    """
    Allocates a new Person object.
    In Python, object creation handles memory allocation, and the
    garbage collector handles deallocation. The __init__ method
    ensures the status is set to 0.
    """
    try:
        return Person()
    except MemoryError:
        return None

def main():
    """Main function with test cases."""
    print("Running Python test cases...")
    for i in range(5):
        print(f"Test Case {i + 1}:")
        p = allocate_person()
        if p is not None:
            print("  Person allocated successfully.")
            print(f"  Person status: {p.status}")
        else:
            print("  Person allocation failed (MemoryError).")
        # No need to manually free memory in Python

if __name__ == "__main__":
    main()