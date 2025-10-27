
class Person:
    def __init__(self):
        self.status = 0
        self.name = ""
        self.age = 0

def allocate_person():
    p = Person()
    p.status = 0
    return p

if __name__ == "__main__":
    # Test case 1: Allocate a person and verify status is 0
    person1 = allocate_person()
    print(f"Test 1 - Status: {person1.status}")
    
    # Test case 2: Allocate another person and verify status is 0
    person2 = allocate_person()
    print(f"Test 2 - Status: {person2.status}")
    
    # Test case 3: Modify status and allocate new person
    person1.status = 5
    person3 = allocate_person()
    print(f"Test 3 - Person1 Status: {person1.status}, Person3 Status: {person3.status}")
    
    # Test case 4: Verify multiple allocations
    person4 = allocate_person()
    person5 = allocate_person()
    print(f"Test 4 - Person4 Status: {person4.status}, Person5 Status: {person5.status}")
    
    # Test case 5: Verify objects are different
    print(f"Test 5 - Are person1 and person2 different objects? {person1 is not person2}")
