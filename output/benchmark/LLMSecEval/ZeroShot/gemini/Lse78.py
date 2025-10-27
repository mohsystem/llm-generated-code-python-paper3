import sys

class Person:
    """A simple class representing a person."""
    def __init__(self, person_id):
        """
        Constructor for Person. In Python, __init__ is called after memory is allocated.
        """
        self.id = person_id
        # Explicitly set status to 0 as per the requirement.
        self.status = 0

    def __str__(self):
        """String representation of the Person object."""
        return f"Person(id={self.id}, status={self.status})"

def allocate_person(person_id):
    """
    Allocates a new Person object.
    In Python, memory allocation is handled automatically when a class constructor is called.
    If memory allocation fails, a MemoryError is raised.
    
    Args:
        person_id: The identifier for the new person.
        
    Returns:
        A new Person object, or None if allocation fails.
    """
    try:
        # Calling the constructor allocates memory and initializes the object.
        person = Person(person_id)
        return person
    except MemoryError:
        # Securely handle the case where memory cannot be allocated.
        return None

def main():
    """Main function with 5 test cases."""
    print("Running 5 test cases...")
    # List to hold the created objects. In Python, this keeps them from being garbage collected.
    people = []
    
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        person_instance = allocate_person(i)
        
        # Securely check if the allocation was successful.
        if person_instance is not None:
            people.append(person_instance)
            print(f"Successfully allocated: {person_instance}")
        else:
            sys.stderr.write(f"Memory allocation failed for person with id {i}\n")

    # In Python, memory is automatically deallocated by the garbage collector
    # when objects are no longer referenced. No manual cleanup is needed.
    print("\nProgram finished. Memory will be reclaimed by the garbage collector.")

if __name__ == "__main__":
    main()