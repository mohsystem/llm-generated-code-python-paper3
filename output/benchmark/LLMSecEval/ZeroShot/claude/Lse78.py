
class Person:
    def __init__(self, name="", age=0):
        self.name = name
        self.age = age
        self.status = 0
    
    def __str__(self):
        return f"Person(name='{self.name}', age={self.age}, status={self.status})"

def allocate_person(name, age):
    person = Person(name, age)
    return person

if __name__ == "__main__":
    # Test case 1
    p1 = allocate_person("Alice", 25)
    print(f"Test 1: {p1}")
    
    # Test case 2
    p2 = allocate_person("Bob", 30)
    print(f"Test 2: {p2}")
    
    # Test case 3
    p3 = allocate_person("Charlie", 35)
    print(f"Test 3: {p3}")
    
    # Test case 4
    p4 = allocate_person("David", 40)
    print(f"Test 4: {p4}")
    
    # Test case 5
    p5 = allocate_person("Eve", 28)
    print(f"Test 5: {p5}")
