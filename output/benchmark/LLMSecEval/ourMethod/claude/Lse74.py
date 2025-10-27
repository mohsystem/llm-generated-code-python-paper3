
import ctypes
from typing import Optional

class Person(ctypes.Structure):
    """Person structure with status field"""
    _fields_ = [("status", ctypes.c_int)]

def allocate_person() -> Optional[Person]:
    """\n    Allocates memory for a Person structure and initializes status to 0.\n    \n    Returns:\n        Person object with status initialized to 0, or None on allocation failure\n    """
    try:
        # Allocate memory for Person structure
        # Python's ctypes handles memory allocation
        person = Person()
        
        # Initialize status field to 0
        person.status = 0
        
        return person
    except Exception:
        # Return None on allocation failure (fail closed)
        return None

def main():
    """Test the allocate_person function with 5 test cases"""
    print("Testing Person allocation:")
    
    # Test case 1: Allocate a single person
    person1 = allocate_person()
    if person1:
        print(f"Test 1 - Person allocated with status: {person1.status}")
    else:
        print("Test 1 - Allocation failed")
    
    # Test case 2: Allocate another person
    person2 = allocate_person()
    if person2:
        print(f"Test 2 - Person allocated with status: {person2.status}")
    else:
        print("Test 2 - Allocation failed")
    
    # Test case 3: Verify status is 0
    person3 = allocate_person()
    if person3:
        print(f"Test 3 - Status is 0: {person3.status == 0}")
    else:
        print("Test 3 - Allocation failed")
    
    # Test case 4: Allocate multiple persons
    people = []
    for i in range(5):
        p = allocate_person()
        if p:
            people.append(p)
    print(f"Test 4 - Allocated {len(people)} persons")
    
    # Test case 5: Verify all have status 0
    person4 = allocate_person()
    person5 = allocate_person()
    if person4 and person5:
        all_zero = (person4.status == 0) and (person5.status == 0)
        print(f"Test 5 - All status fields are 0: {all_zero}")
    else:
        print("Test 5 - Allocation failed")

if __name__ == "__main__":
    main()
