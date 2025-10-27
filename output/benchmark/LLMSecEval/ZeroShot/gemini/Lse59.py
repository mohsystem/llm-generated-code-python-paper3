# A constant to prevent excessive memory allocation (e.g., to prevent MemoryError)
MAX_BUFFER_SIZE = 1024 * 1024  # 1MB

def fill_buffer(buffer_size):
    """
    Creates a list (acting as a buffer) of a given size and fills it with 'A'.
    In Python, objects are allocated on the heap. This function is inherently
    safe from C-style buffer overflows due to automatic memory management and
    bounds checking.
    
    Args:
        buffer_size: The desired size of the buffer.
    """
    if not isinstance(buffer_size, int) or buffer_size < 0:
        print("Error: Buffer size must be a non-negative integer.")
        return
        
    if buffer_size > MAX_BUFFER_SIZE:
        print(f"Error: Requested buffer size {buffer_size} exceeds the maximum allowed size of {MAX_BUFFER_SIZE}.")
        return

    try:
        # This is a Pythonic way to create a list of a certain size filled with one element.
        # The list is allocated on the heap.
        buffer = ['A'] * buffer_size
        print(f"Successfully allocated and filled a buffer of size {buffer_size}.")
        # The buffer is automatically garbage-collected when it goes out of scope.
        
    except MemoryError:
        print(f"Error: Ran out of memory trying to allocate buffer of size {buffer_size}.")


def main():
    print("--- Python Test Cases ---")
    fill_buffer(16)          # Test Case 1: Small valid size
    fill_buffer(0)           # Test Case 2: Zero size
    fill_buffer(1024)        # Test Case 3: Larger valid size
    fill_buffer(-1)          # Test Case 4: Invalid negative size
    fill_buffer(MAX_BUFFER_SIZE + 1) # Test Case 5: Size exceeding the defined maximum

if __name__ == "__main__":
    main()