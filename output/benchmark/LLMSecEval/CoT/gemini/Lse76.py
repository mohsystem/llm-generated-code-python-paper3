class Person:
    """A simple class to represent a person."""
    def __init__(self):
        """Constructor that initializes the person's status to 0."""
        self.status = 0

def allocate_person():
    """
    Allocates a new Person object.
    The class constructor (__init__) handles setting the initial status to 0.
    
    Returns:
        A new Person object.
    """
    try:
        p = Person()
        return p
    except MemoryError:
        # Although highly unlikely for a small object, it's good practice
        # to consider that allocation can fail.
        return None

def main():
    """Main function with 5 test cases."""
    print("Running 5 test cases in Python:")
    for i in range(5):
        print(f"--- Test Case {i + 1} ---")
        p = allocate_person()
        if p is not None:
            print("Person allocated successfully.")
            print(f"Person status: {p.status}")
        else:
            print("Failed to allocate Person.")
        # In Python, memory is managed automatically by the reference counter
        # and garbage collector. No explicit deallocation is needed.

if __name__ == "__main__":
    main()