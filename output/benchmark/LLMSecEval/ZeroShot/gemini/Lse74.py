import sys

class Person:
    """A simple class to represent a person."""
    def __init__(self, person_id):
        """
        Constructor for Person. In Python, __init__ is called after memory is allocated.
        We initialize the instance attributes here.
        """
        self.person_id = person_id
        self.status = 0  # Set the status field to 0 as required.

def create_person(person_id):
    """
    Allocates a new person and sets the status field to 0.
    In Python, this is done by instantiating the class.
    MemoryError is raised on allocation failure.
    """
    try:
        # Instantiation handles memory allocation and initialization via __init__.
        return Person(person_id)
    except MemoryError:
        # This error is critical and usually not recoverable.
        # Logging the error is recommended in a real application.
        sys.stderr.write("Fatal: Out of memory. Cannot create new Person.\n")
        return None

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    for i in range(5):
        print(f"Test Case {i + 1}:")
        p = create_person(i)
        if p:
            # Python's garbage collector will automatically deallocate memory
            # when the object is no longer referenced.
            print(f"  Successfully created Person with ID: {p.person_id}")
            print(f"  Person status field is: {p.status}")
        else:
            print("  Failed to create Person.")
            break

if __name__ == "__main__":
    main()