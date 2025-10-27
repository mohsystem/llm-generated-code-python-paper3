
class Person:
    def __init__(self):
        self.status = 0
        self.name = ""
    
    def __str__(self):
        return f"Person(status={self.status}, name='{self.name}')"

def create_person(name):
    person = Person()
    person.status = 0
    if name is not None:
        person.name = name
    else:
        person.name = ""
    return person

if __name__ == "__main__":
    # Test case 1: Create person with name "John"
    person1 = create_person("John")
    print(f"Test 1: {person1}")
    
    # Test case 2: Create person with name "Alice"
    person2 = create_person("Alice")
    print(f"Test 2: {person2}")
    
    # Test case 3: Create person with name "Bob"
    person3 = create_person("Bob")
    print(f"Test 3: {person3}")
    
    # Test case 4: Create person with empty name
    person4 = create_person("")
    print(f"Test 4: {person4}")
    
    # Test case 5: Create person with None name (secure handling)
    person5 = create_person(None)
    print(f"Test 5: {person5}")
