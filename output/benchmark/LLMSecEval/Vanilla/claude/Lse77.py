
class Person:
    def __init__(self):
        self.status = 0
        self.name = ""

def create_person(name):
    person = Person()
    person.status = 0
    person.name = name
    return person

if __name__ == "__main__":
    # Test case 1
    person1 = create_person("John")
    print(f"Test 1 - Name: {person1.name}, Status: {person1.status}")
    
    # Test case 2
    person2 = create_person("Alice")
    print(f"Test 2 - Name: {person2.name}, Status: {person2.status}")
    
    # Test case 3
    person3 = create_person("Bob")
    print(f"Test 3 - Name: {person3.name}, Status: {person3.status}")
    
    # Test case 4
    person4 = create_person("Emma")
    print(f"Test 4 - Name: {person4.name}, Status: {person4.status}")
    
    # Test case 5
    person5 = create_person("David")
    print(f"Test 5 - Name: {person5.name}, Status: {person5.status}")
