
class Person:
    def __init__(self, status, name):
        self.status = status
        self.name = name if name is not None else ""
    
    def __str__(self):
        return f"Person(status={self.status}, name='{self.name}')"


def create_person():
    """\n    Creates a new Person object with status=0 and name="John"\n    Returns a reference to the Person object\n    """
    person = Person(0, "John")
    return person


def main():
    # Test case 1: Basic creation
    person1 = create_person()
    print(f"Test 1: {person1}")
    
    # Test case 2: Verify status
    person2 = create_person()
    print(f"Test 2 - Status: {person2.status}")
    
    # Test case 3: Verify name
    person3 = create_person()
    print(f"Test 3 - Name: {person3.name}")
    
    # Test case 4: Multiple instances
    person4 = create_person()
    person5 = create_person()
    print(f"Test 4 - Multiple: {person4}, {person5}")
    
    # Test case 5: Object independence
    person6 = create_person()
    print(f"Test 5 - Independent: {person6}")


if __name__ == "__main__":
    main()
