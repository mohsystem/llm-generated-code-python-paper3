
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
    # Test case 1: Allocate a person and check status
    p1 = allocate_person()
    print(f"Test 1 - Status: {p1.status}")
    
    # Test case 2: Allocate another person and verify independence
    p2 = allocate_person()
    p2.status = 1
    print(f"Test 2 - P1 Status: {p1.status}, P2 Status: {p2.status}")
    
    # Test case 3: Allocate third person
    p3 = allocate_person()
    print(f"Test 3 - Status: {p3.status}")
    
    # Test case 4: Allocate fourth person
    p4 = allocate_person()
    print(f"Test 4 - Status: {p4.status}")
    
    # Test case 5: Allocate fifth person
    p5 = allocate_person()
    print(f"Test 5 - Status: {p5.status}")
