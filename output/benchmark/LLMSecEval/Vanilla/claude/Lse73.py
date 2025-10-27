
class Person:
    def __init__(self, name="", age=0, height=0.0):
        self.name = name
        self.age = age
        self.height = height

def allocate_person():
    return Person()

if __name__ == "__main__":
    # Test case 1
    p1 = allocate_person()
    p1.name = "John"
    p1.age = 25
    p1.height = 5.9
    print(f"Test 1: {p1.name}, {p1.age}, {p1.height}")
    
    # Test case 2
    p2 = allocate_person()
    p2.name = "Alice"
    p2.age = 30
    p2.height = 5.5
    print(f"Test 2: {p2.name}, {p2.age}, {p2.height}")
    
    # Test case 3
    p3 = allocate_person()
    p3.name = "Bob"
    p3.age = 35
    p3.height = 6.1
    print(f"Test 3: {p3.name}, {p3.age}, {p3.height}")
    
    # Test case 4
    p4 = allocate_person()
    p4.name = "Carol"
    p4.age = 28
    p4.height = 5.7
    print(f"Test 4: {p4.name}, {p4.age}, {p4.height}")
    
    # Test case 5
    p5 = allocate_person()
    p5.name = "David"
    p5.age = 40
    p5.height = 5.8
    print(f"Test 5: {p5.name}, {p5.age}, {p5.height}")
