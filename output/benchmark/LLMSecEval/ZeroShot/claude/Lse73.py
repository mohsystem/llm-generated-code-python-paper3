
class Person:
    def __init__(self, name, age, height):
        self.name = name
        self.age = age
        self.height = height
    
    def __str__(self):
        return f"Person{{name='{self.name}', age={self.age}, height={self.height}}}"

def allocate_person(name, age, height):
    return Person(name, age, height)

if __name__ == "__main__":
    # Test case 1
    p1 = allocate_person("John Doe", 30, 5.9)
    print(f"Test 1: {p1}")
    
    # Test case 2
    p2 = allocate_person("Jane Smith", 25, 5.5)
    print(f"Test 2: {p2}")
    
    # Test case 3
    p3 = allocate_person("Bob Johnson", 45, 6.1)
    print(f"Test 3: {p3}")
    
    # Test case 4
    p4 = allocate_person("Alice Williams", 35, 5.7)
    print(f"Test 4: {p4}")
    
    # Test case 5
    p5 = allocate_person("Charlie Brown", 28, 5.8)
    print(f"Test 5: {p5}")
