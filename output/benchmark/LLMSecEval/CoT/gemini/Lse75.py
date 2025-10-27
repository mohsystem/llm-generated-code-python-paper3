class Person:
    """A simple class to represent a person with a status."""
    _counter = 0

    def __init__(self):
        """
        Constructor for the Person class.
        This method is called when a new object is created.
        It initializes the status to 0.
        """
        # Set status to 0 as required
        self.status = 0
        Person._counter += 1
        self.id = Person._counter

    def __str__(self):
        return f"Person(id={self.id}, status={self.status})"

def allocate_person():
    """
    Allocates a new person object. The class constructor handles setting
    the initial status to 0.
    
    Returns:
        A new Person object or None if allocation fails.
    """
    try:
        # In Python, creating an instance of a class allocates memory
        # and calls the __init__ constructor.
        return Person()
    except MemoryError:
        # This handles the rare case of the system running out of memory.
        print("Error: Failed to allocate memory.")
        return None

def main():
    """Main function to run test cases."""
    print("--- Python Test Cases ---")
    people = []
    for i in range(5):
        print(f"Test Case {i + 1}:")
        p = allocate_person()
        if p is not None:
            people.append(p)
            print(f"  Allocated: {p}")
            print(f"  Person status is: {p.status}")
        else:
            print("  Memory allocation failed.")
    
    # In Python, memory is managed automatically by the garbage collector.
    # There is no need for manual deallocation like in C/C++.
    print("\nMemory will be managed by the Garbage Collector.")

if __name__ == "__main__":
    main()