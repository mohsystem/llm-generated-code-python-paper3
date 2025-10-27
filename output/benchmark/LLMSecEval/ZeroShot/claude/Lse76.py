
class Person:
    def __init__(self):
        self.status = 0
        self.name = None
        self.age = None

def allocate_person():
    person = Person()
    person.status = 0
    return person

def main():
    # Test case 1: Allocate single person
    p1 = allocate_person()
    print(f"Test 1 - Person status: {p1.status}")
    
    # Test case 2: Allocate multiple persons
    p2 = allocate_person()
    p3 = allocate_person()
    print(f"Test 2 - Person2 status: {p2.status}, Person3 status: {p3.status}")
    
    # Test case 3: Verify independence
    p1.status = 5
    p4 = allocate_person()
    print(f"Test 3 - Person1 status: {p1.status}, Person4 status: {p4.status}")
    
    # Test case 4: Allocate and set properties
    p5 = allocate_person()
    p5.name = "John"
    p5.age = 30
    print(f"Test 4 - Person5 status: {p5.status}, Name: {p5.name}")
    
    # Test case 5: Multiple allocations in loop
    for i in range(3):
        p = allocate_person()
        print(f"Test 5 - Iteration {i} status: {p.status}")

if __name__ == "__main__":
    main()
