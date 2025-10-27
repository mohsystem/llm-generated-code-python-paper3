
class Person:
    def __init__(self):
        self.status = 0
        self.name = ""
        self.age = 0

def allocate_person():
    person = Person()
    person.status = 0
    return person

if __name__ == "__main__":
    # Test case 1: Basic allocation
    person1 = allocate_person()
    print(f"Test 1 - Status: {person1.status}")
    
    # Test case 2: Multiple allocations
    person2 = allocate_person()
    print(f"Test 2 - Status: {person2.status}")
    
    # Test case 3: Verify independence
    person1.status = 1
    person3 = allocate_person()
    print(f"Test 3 - Status: {person3.status}")
    
    # Test case 4: Check not None
    person4 = allocate_person()
    print(f"Test 4 - Not None: {person4 is not None}")
    
    # Test case 5: Verify initial values
    person5 = allocate_person()
    print(f"Test 5 - Status: {person5.status}, Age: {person5.age}")
