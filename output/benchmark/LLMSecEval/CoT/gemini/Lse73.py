class Person:
    """A simple class to represent a person."""
    def __init__(self):
        self.age = 0
        self.height = 0.0

    def __str__(self):
        return f"Person(age={self.age}, height={self.height})"

def allocate_person():
    """
    Allocates memory for a new Person object.
    In Python, memory is managed automatically. Object instantiation allocates
    the necessary memory. This is equivalent to allocating sizeof(Person) and
    returning a reference.
    :return: A new Person object instance.
    """
    try:
        # This allocates memory and initializes the object
        return Person()
    except MemoryError:
        # This case is extremely rare in modern systems but is the correct way
        # to handle allocation failure in Python.
        return None

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    for i in range(1, 6):
        print(f"Test Case {i}:")
        
        # 1. Allocate memory for a Person object
        p = allocate_person()

        if p is not None:
            # 2. Initialize the object's attributes
            p.age = 20 + i
            p.height = 170.5 + i

            # 3. Print the object's state
            print(f"  Allocated and initialized: {p}")

            # 4. Memory is automatically deallocated by the Garbage Collector
            # when the object's reference count drops to zero.
            print("  Memory will be deallocated automatically by GC.")
        else:
            print("  Memory allocation failed.")
        print()

if __name__ == "__main__":
    main()