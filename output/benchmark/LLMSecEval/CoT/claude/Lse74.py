
class Person:
    def __init__(self):
        self.status = 0
        self.name = ""
        self.age = 0

def allocate_person():
    try:
        person = Person()
        person.status = 0
        return person
    except MemoryError as e:
        print(f"Memory allocation failed: {e}")
        return None

def main():
    print("Test Case 1: Basic allocation")
    p1 = allocate_person()
    if p1 is not None:
        print(f"Person allocated, status: {p1.status}")
    
    print("\\nTest Case 2: Multiple allocations")
    p2 = allocate_person()
    p3 = allocate_person()
    if p2 is not None and p3 is not None:
        print("Multiple persons allocated successfully")
    
    print("\\nTest Case 3: Verify status initialization")
    p4 = allocate_person()
    if p4 is not None:
        print(f"Status is zero: {p4.status == 0}")
    
    print("\\nTest Case 4: Modify status")
    p5 = allocate_person()
    if p5 is not None:
        p5.status = 1
        print(f"Modified status: {p5.status}")
    
    print("\\nTest Case 5: Null check")
    p6 = allocate_person()
    print(f"Allocation result: {'Success' if p6 is not None else 'Failed'}")

if __name__ == "__main__":
    main()
