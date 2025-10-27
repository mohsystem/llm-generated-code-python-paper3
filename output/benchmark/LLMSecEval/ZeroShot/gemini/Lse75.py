import sys

# In Python, memory management is automatic.
# The class constructor (__init__) is called upon instantiation.
class Person:
    """A class to represent a person."""
    def __init__(self, person_id):
        """
        Constructor for the Person class.
        This is the secure way to ensure every instance is
        properly initialized.
        """
        self.person_id = person_id
        # Set the status to 0 upon creation.
        self.status = 0

    def __str__(self):
        return f"Person(id={self.person_id}, status={self.status})"

def create_person(person_id):
    """
    Allocates a new person object.
    In Python, this is done by instantiating the class.
    The interpreter handles the memory allocation.
    
    Args:
        person_id: The identifier for the new person.
    
    Returns:
        A new Person object.
    """
    try:
        # Instantiation allocates memory and calls __init__.
        return Person(person_id)
    except MemoryError:
        # This exception is raised if the system runs out of memory.
        print(f"Error: Failed to allocate memory for person with id {person_id}.", file=sys.stderr)
        return None

def main():
    """Main function with test cases."""
    print("Python Test Cases:")
    people = []
    
    # 5 Test Cases
    for i in range(1, 6):
        p = create_person(i * 10)
        if p:
            people.append(p)
            print(f"Test Case {i}: Created {p}")
        else:
            print(f"Test Case {i}: Person creation failed.")
    
    # Memory is automatically managed by Python's garbage collector.
    print(f"Total people created: {len(people)}")

if __name__ == "__main__":
    main()