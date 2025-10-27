# In Python, objects are allocated on the heap. The name 'buffer' exists in the
# local scope (stack frame), but it refers to an object on the heap.
# True stack allocation of a variable-sized buffer is not possible.
# This function simulates the requested behavior in an idiomatic Python way.
MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10 MB limit for safety

def allocate_and_fill_buffer(buffer_size):
    """
    Creates a bytearray of a given size and fills it with the character 'A'.

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
        # The bytearray object is created on the heap.
        buffer = bytearray(buffer_size)

        # Fill the buffer with the ASCII value of 'A'.
        # This is an efficient way to initialize it.
        if buffer_size > 0:
            buffer[:] = b'A' * buffer_size
        
        print(f"Successfully created and filled a buffer of size {buffer_size} with 'A'.")
        # The buffer is garbage collected after it goes out of scope.

    except MemoryError:
        print(f"Error: Ran out of memory trying to allocate buffer of size {buffer_size}.")


def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    # Test Case 1: A small, typical size
    allocate_and_fill_buffer(16)
    # Test Case 2: Size 1
    allocate_and_fill_buffer(1)
    # Test Case 3: Size 0 (edge case)
    allocate_and_fill_buffer(0)
    # Test Case 4: A larger, but valid size
    allocate_and_fill_buffer(1024)
    # Test Case 5: A size that is too large and will be caught by our security check
    allocate_and_fill_buffer(20_000_000)

if __name__ == "__main__":
    main()