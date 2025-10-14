import sys

def demonstrate_resource_management(size):
    """
    Demonstrates dynamic memory allocation in Python.
    Memory is allocated when objects are created. Deallocation is handled
    automatically by Python's garbage collector (which uses reference counting
    and a cycle detector). 'del' decrements the reference count. When the
    count reaches zero, the object is deallocated.
    """
    if size <= 0:
        print("Size must be positive. No allocation performed.")
        return

    allocated_list = None
    try:
        # 1. Dynamic Allocation: Creating a list object.
        allocated_list = [0] * size
        print(f"Successfully allocated a list with {size} elements.")
        # Use the resource...
        allocated_list[0] = 100
        print(f"First element: {allocated_list[0]}")

    except MemoryError:
        print(f"Memory allocation failed for size {size}.", file=sys.stderr)
    finally:
        # 2. Deallocation (making eligible for GC):
        # The 'del' keyword removes the reference 'allocated_list' to the list object.
        # If this is the last reference, the object's memory will be reclaimed.
        if allocated_list is not None:
            del allocated_list
            print("Resource reference deleted. Object is now eligible for garbage collection.")

def main():
    """ Main function with 5 test cases """
    print("--- Python Dynamic Memory Management ---")
    # 5 Test Cases
    demonstrate_resource_management(10)
    print("--------------------")
    demonstrate_resource_management(1000)
    print("--------------------")
    demonstrate_resource_management(0)
    print("--------------------")
    demonstrate_resource_management(50000)
    print("--------------------")
    demonstrate_resource_management(10**8) # A large allocation
    print("--- End of Python Demo ---")

if __name__ == "__main__":
    main()