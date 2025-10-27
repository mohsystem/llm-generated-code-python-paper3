class Person:
    def __init__(self):
        # In Python, the __init__ method initializes the object's state.
        # We set the status here.
        self.status = 0

def allocate_person():
    """
    Allocates a new person and sets the status field to 0.
    In Python, this means creating a new instance of the Person class.
    """
    return Person()

def main():
    """ Main function with 5 test cases """
    print("--- Python Test Cases ---")
    for i in range(1, 6):
        person = allocate_person()
        print(f"Test Case {i}:")
        if person is not None:
            # id() gives a unique integer for the object's lifetime (similar to a memory address)
            print(f"  Person allocated at: {id(person)}")
            print(f"  Person status: {person.status}")
        else:
            print("  Allocation failed.")

if __name__ == "__main__":
    main()