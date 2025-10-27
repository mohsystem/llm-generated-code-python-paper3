import sys
from typing import Optional

class Person:
    """Represents a person with a name and status."""
    def __init__(self, name: str):
        """
        Initializes a Person object.
        Sets status to 0 as required.
        """
        if not name:
            raise ValueError("Name cannot be empty.")
        self.name = name
        self.status = 0

    def __str__(self) -> str:
        return f"Person(name='{self.name}', status={self.status})"

def create_person(name: str) -> Optional[Person]:
    """
    Allocates a new person and sets the status to 0.
    In Python, this is handled by the class constructor.
    This function acts as a safe factory.
    """
    try:
        return Person(name)
    except ValueError as e:
        print(f"Error creating person: {e}", file=sys.stderr)
        return None
    except MemoryError:
        print("Error creating person: Out of memory.", file=sys.stderr)
        return None

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")

    # Test Case 1
    person1 = create_person("Alice")
    if person1:
        print(f"Test Case 1: Created {person1}")

    # Test Case 2
    person2 = create_person("Bob")
    if person2:
        print(f"Test Case 2: Created {person2}")

    # Test Case 3
    person3 = create_person("Charlie")
    if person3:
        print(f"Test Case 3: Created {person3}")

    # Test Case 4
    person4 = create_person("Diana")
    if person4:
        print(f"Test Case 4: Created {person4}")

    # Test Case 5: Invalid input
    person5 = create_person("")
    if not person5:
        print("Test Case 5: Failed to create person as expected for empty name.")

    # In Python, memory is managed by the Garbage Collector.
    # No explicit deallocation is needed.
    print("\n--- Test Cases Finished ---")

if __name__ == "__main__":
    main()