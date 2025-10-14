import sys

def manage_memory(size: int):
    """
    Demonstrates dynamic memory allocation and deallocation in Python.
    Python's memory manager handles this automatically. Objects are allocated
    on creation and deallocated when their reference count drops to zero.

    :param size: The number of elements for the list.
    """
    if size <= 0:
        print(f"Size must be positive. Cannot allocate memory for size: {size}")
        return
        
    print(f"--- Python: Managing memory for size {size} ---")
    
    # 1. Dynamic Allocation: A list is a dynamically allocated object.
    try:
        dynamic_list = [0] * size
        # id() gives a unique identifier for the object, similar to a memory address.
        print(f"Allocated a list of {size} integers at id: {id(dynamic_list)}")
    except MemoryError:
        print(f"MemoryError: Failed to allocate memory for size {size}.")
        print("------------------------------------------\n")
        return

    # 2. Using the allocated memory
    for i in range(size):
        dynamic_list[i] = i * 10
    print("Successfully used the allocated memory.")
    
    # 3. Deallocation: Handled by Python's garbage collector.
    # 'del' decrements the reference count. When it reaches 0, memory is freed.
    del dynamic_list
    print("Memory reference removed. The object is now eligible for garbage collection.")
    print("------------------------------------------\n")

if __name__ == "__main__":
    # 5 test cases
    manage_memory(10)
    manage_memory(100)
    manage_memory(5)
    manage_memory(0) # Test case for invalid size
    manage_memory(1000)