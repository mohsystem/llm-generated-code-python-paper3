def manage_memory(size):
    """
    Demonstrates dynamic memory allocation and deallocation in Python.
    In Python, memory management is automatic. Allocation happens when an object is created.
    Deallocation occurs when an object's reference count drops to zero.
    
    :param size: The number of elements to allocate in a list.
    """
    if size <= 0:
        print(f"Cannot allocate memory for size {size}.")
        return
        
    print(f"Attempting to allocate memory for a list of {size} elements.")
    
    # 1. Dynamic Allocation: Creating a list
    try:
        dynamic_list = [0] * size
        print(f"Memory allocated successfully for list with id: {id(dynamic_list)}")

        # Using the allocated memory
        dynamic_list[0] = 100
        print(f"First element set to: {dynamic_list[0]}")

        # 2. Dynamic Deallocation: Removing the reference
        print("Deleting the reference to the list, allowing the garbage collector to reclaim memory.")
        del dynamic_list
        
        print(f"Memory for {size} elements is now eligible to be freed.\n")

    except MemoryError:
        print(f"MemoryError: Failed to allocate memory for {size} elements.\n")

def main():
    """Main function with test cases."""
    print("--- Python Memory Management Demo ---")
    # 5 Test Cases
    manage_memory(10)
    manage_memory(1000)
    manage_memory(50000)
    manage_memory(0)
    manage_memory(1)
    print("--- End of Python Demo ---\n")

if __name__ == "__main__":
    main()