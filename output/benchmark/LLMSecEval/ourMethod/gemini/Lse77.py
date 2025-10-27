class Person:
    """A simple class to represent a person."""
    def __init__(self, status, name):
        self.status = status
        self.name = name

    def __str__(self):
        return f"Person[Name: {self.name}, Status: {self.status}]"

def create_person():
    """
    Allocates and initializes a new Person object.
    In Python, memory allocation is handled by the interpreter.
    """
    # "Allocates" a new Person object by instantiating the class.
    return Person(status=0, name="John")

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    for i in range(5):
        print(f"Test Case {i + 1}:")
        person = create_person()
        if person:
            print("  Person created successfully.")
            print(f"  {person}")
        else:
            print("  Failed to create person.")
        # In Python, memory is managed by the Garbage Collector.
        print()

if __name__ == "__main__":
    main()