class Person:
    """A simple class to represent a person."""
    def __init__(self):
        self.status = -1  # Default initial status
        self.age = -1     # Default initial age

def allocate_person():
    """
    Allocates a new Person instance, sets its status to 0,
    and returns it.
    """
    # In Python, creating an instance of a class allocates memory.
    new_person = Person()
    
    # Set the status to 0 as required.
    new_person.status = 0
    
    return new_person

def main():
    """Main function to run test cases."""
    print("--- Python Test Cases ---")
    for i in range(1, 6):
        p = allocate_person()
        # In Python, allocation failure raises a MemoryError.
        # We assume it succeeds for these test cases.
        print(f"Test Case {i}: Allocated Person object. Status: {p.status}")
        # Python's garbage collector handles memory deallocation.

if __name__ == "__main__":
    main()