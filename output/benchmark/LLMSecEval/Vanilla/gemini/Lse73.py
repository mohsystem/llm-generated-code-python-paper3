class Person:
    def __init__(self, name="", age=0):
        self.name = name
        self.age = age

    def __str__(self):
        return f"Person(name='{self.name}', age={self.age})"

def allocate_person():
    """
    Allocates memory for a Person object. In Python, this is done by creating a new instance.
    Returns a reference to the newly created Person object.
    """
    return Person()

def main():
    """
    Main function with 5 test cases.
    """
    print("Python Test Cases:")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        p = allocate_person()
        if p is not None:
            # Initialize the allocated object
            p.name = f"Person {i}"
            p.age = 20 + i
            print(f"Successfully allocated and initialized: {p}")
            # In Python, memory is automatically managed by the Garbage Collector.
            # No need to explicitly deallocate.
        else:
            print("Memory allocation failed.")

if __name__ == "__main__":
    main()