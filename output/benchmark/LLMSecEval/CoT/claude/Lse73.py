
class Person:
    def __init__(self, name="", age=0):
        self.name = name
        self.age = age
    
    def __str__(self):
        return f"Person{{name='{self.name}', age={self.age}}}"

def allocate_person(name="", age=0):
    try:
        person = Person(name, age)
        return person
    except MemoryError as e:
        print(f"Memory allocation failed: {e}")
        return None
    except Exception as e:
        print(f"Allocation error: {e}")
        return None

def main():
    # Test case 1: Basic allocation
    p1 = allocate_person()
    if p1 is not None:
        p1.name = "Alice"
        p1.age = 25
        print(f"Test 1: {p1}")
    
    # Test case 2: Allocation with parameters
    p2 = allocate_person("Bob", 30)
    if p2 is not None:
        print(f"Test 2: {p2}")
    
    # Test case 3: Multiple allocations
    p3 = allocate_person("Charlie", 35)
    if p3 is not None:
        print(f"Test 3: {p3}")
    
    # Test case 4: Null validation
    p4 = allocate_person("Diana", 28)
    if p4 is not None:
        print(f"Test 4: {p4}")
    else:
        print("Test 4: Allocation failed")
    
    # Test case 5: Zero age
    p5 = allocate_person("Eve", 0)
    if p5 is not None:
        print(f"Test 5: {p5}")

if __name__ == "__main__":
    main()
