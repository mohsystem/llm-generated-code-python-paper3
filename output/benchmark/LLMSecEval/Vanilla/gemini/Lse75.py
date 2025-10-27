class Person:
    """A simple class to represent a person."""
    def __init__(self, person_id):
        # The __init__ method is called upon object creation.
        # We set the status to 0 here.
        self.id = person_id
        self.status = 0

    def __repr__(self):
        return f"Person(id={self.id}, status={self.status})"

def allocate_person(person_id):
    """
    Allocates a new Person object and returns it.
    The status is set to 0 by the constructor (__init__).
    """
    return Person(person_id)

def main():
    """Main function to run test cases."""
    print("Python Test Cases:")
    people = []

    # 5 Test cases
    for i in range(5):
        person = allocate_person(i + 1)
        people.append(person)
        # id() gives a unique integer for an object, similar to a memory address.
        print(f"Test Case {i + 1}: Allocated {person} at id {id(person)}")

    # Memory is automatically managed by Python's garbage collector.
    # There is no need to manually deallocate memory.

if __name__ == "__main__":
    main()