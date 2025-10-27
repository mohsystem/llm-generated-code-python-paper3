import sys
from typing import Optional

class Person:
    """A simple class representing a person."""
    def __init__(self, name: str, age: int):
        if not name or not isinstance(name, str):
            raise ValueError("Name must be a non-empty string.")
        if not isinstance(age, int) or age < 0:
            raise ValueError("Age must be a non-negative integer.")
        self.name = name
        self.age = age

    def __str__(self) -> str:
        return f"Person(name='{self.name}', age={self.age})"

def allocate_person(name: str, age: int) -> Optional[Person]:
    """
    Allocates memory for a Person object and returns a reference to it.
    In Python, object instantiation handles memory allocation automatically.
    
    Args:
        name: The name of the person.
        age: The age of the person.
        
    Returns:
        A new Person object instance, or None on failure.
    """
    try:
        # Instantiating the class allocates memory for the object.
        return Person(name, age)
    except ValueError as e:
        print(f"Error: Invalid argument for person: {e}", file=sys.stderr)
        return None
    except MemoryError:
        # This is the equivalent of a failed allocation.
        print("FATAL: Failed to allocate memory for a new Person object.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def main():
    """Main function with test cases."""
    print("--- Running Python Test Cases ---")
    people = []

    # Test Case 1
    person1 = allocate_person("Alice", 30)
    if person1:
        people.append(person1)
        print(f"Test Case 1: Allocated {person1}")

    # Test Case 2
    person2 = allocate_person("Bob", 25)
    if person2:
        people.append(person2)
        print(f"Test Case 2: Allocated {person2}")

    # Test Case 3
    person3 = allocate_person("Charlie", 35)
    if person3:
        people.append(person3)
        print(f"Test Case 3: Allocated {person3}")

    # Test Case 4
    person4 = allocate_person("Diana", 28)
    if person4:
        people.append(person4)
        print(f"Test Case 4: Allocated {person4}")

    # Test Case 5
    person5 = allocate_person("Eve", 40)
    if person5:
        people.append(person5)
        print(f"Test Case 5: Allocated {person5}")
    
    # In Python, memory is managed by the reference counting and garbage collection.
    # When the 'people' list and its elements are no longer referenced,
    # the memory is automatically reclaimed.
    
    print(f"Total people allocated: {len(people)}")
    print("--- Python Test Cases Complete ---")


if __name__ == "__main__":
    main()