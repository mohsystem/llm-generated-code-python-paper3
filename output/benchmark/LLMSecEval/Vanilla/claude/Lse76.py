
class Person:
    def __init__(self):
        self.status = 0

def allocate_person():
    person = Person()
    person.status = 0
    return person

if __name__ == "__main__":
    # Test case 1
    p1 = allocate_person()
    print(f"Test 1 - Person status: {p1.status}")
    
    # Test case 2
    p2 = allocate_person()
    print(f"Test 2 - Person status: {p2.status}")
    
    # Test case 3
    p3 = allocate_person()
    print(f"Test 3 - Person status: {p3.status}")
    
    # Test case 4
    p4 = allocate_person()
    print(f"Test 4 - Person status: {p4.status}")
    
    # Test case 5
    p5 = allocate_person()
    print(f"Test 5 - Person status: {p5.status}")
