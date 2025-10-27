import ctypes

class Person:
    """A simple class to represent a person."""
    def __init__(self, status, name):
        self.status = status
        self.name = name

    def __str__(self):
        # id() gives a memory address-like unique identifier for the object
        return f"Person(status={self.status}, name='{self.name}') at memory id: {id(self)}"

def create_person():
    """
    Creates a new Person object. In Python, object instantiation handles memory allocation.
    The object is initialized with status=0 and name="John".

    Returns:
        A reference to the newly created Person object.
    """
    # Creating an instance of a class allocates memory for it.
    person = Person(status=0, name="John")
    return person

def main():
    """Main function to run test cases."""
    print("--- Python Test Cases ---")
    for i in range(5):
        print(f"Test Case {i + 1}:")
        # Python's garbage collector handles memory deallocation automatically.
        p = create_person()
        if p is not None:
            print(f"  Successfully created person: {p}")
        else:
            print("  Failed to create person.")

if __name__ == "__main__":
    main()