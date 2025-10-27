import sys

class Person:
    """A simple class representing a person."""
    def __init__(self):
        """Constructor to initialize a new Person object.
           The status is set to 0 upon allocation/instantiation.
        """
        self.status = 0

def allocate_person():
    """
    Allocates a new Person object.
    In Python, this is done by instantiating the class.
    Memory management is automatic.
    :return: A new Person object with status set to 0, or None on failure.
    """
    try:
        # Instantiation allocates memory and calls __init__
        return Person()
    except MemoryError:
        # Allocation can fail if the system is out of memory
        sys.stderr.write("Failed to allocate memory for Person.\n")
        return None

def main():
    """Main function to run test cases."""
    print("--- Python Test Cases ---")
    for i in range(5):
        print(f"Test Case {i + 1}")
        
        p = allocate_person()
        
        if p is not None:
            print("Person allocated successfully.")
            print(f"Person status: {p.status}")
        else:
            print("Person allocation failed.")
            
        # No explicit free needed in Python. The garbage collector reclaims memory
        # when the object's reference count drops to zero.
        print("--------------------")

if __name__ == "__main__":
    main()