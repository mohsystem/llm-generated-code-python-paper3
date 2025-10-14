import sys
from typing import List

def demonstrate_allocation(size: int) -> None:
    """
    Dynamically allocates a list, uses it, and then deallocates it.
    
    Args:
        size: The number of integers to allocate space for.
    """
    if size < 0:
        print("Error: Cannot allocate a negative-sized list.")
        return
    
    if size == 0:
        print("Allocating a zero-sized list.")

    print(f"Attempting to allocate memory for {size} integers...")
    
    data: List[int] = []
    try:
        # 1. Dynamic Allocation
        # In Python, this happens when creating a list or other object.
        data = [0] * size
        print(f"Successfully allocated approximately {sys.getsizeof(data)} bytes.")

        # 2. Use the allocated memory
        for i in range(size):
            data[i] = i * 2
        
        if size > 0:
            print(f"Used memory. First element: {data[0]}, Last element: {data[-1]}")
        else:
            print("Used memory. List is empty.")

    except MemoryError:
        print(f"Error: Memory allocation failed for size {size}.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        # 3. Deallocation
        # In Python, this is handled by the garbage collector when the reference count drops to zero.
        # We can explicitly delete the reference.
        del data
        print("Memory reference released. The resource is now eligible for garbage collection.")
        print("----------------------------------------")

def main() -> None:
    """Main function with test cases."""
    print("--- Python Dynamic Memory Demonstration ---")
    # Test case 1: A small, valid size
    demonstrate_allocation(10)
    # Test case 2: A larger size
    demonstrate_allocation(100000)
    # Test case 3: A zero size
    demonstrate_allocation(0)
    # Test case 4: A negative size (invalid)
    demonstrate_allocation(-5)
    # Test case 5: A very large size that might cause a MemoryError
    try:
        # In 64-bit Python, a list of this size can exceed typical RAM
        demonstrate_allocation(10**9)
    except MemoryError:
        print("Caught MemoryError as expected for very large allocation.", file=sys.stderr)


if __name__ == "__main__":
    main()