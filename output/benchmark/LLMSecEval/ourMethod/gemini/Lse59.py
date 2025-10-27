import sys

MAX_BUFFER_SIZE = 4096

def overwrite_buffer(buffer_size: int):
    """
    Allocates a local buffer of a given size and overwrites it with 'A'.
    The buffer size is validated to prevent excessive memory allocation.
    In Python, objects are heap-allocated; a local variable holding the
    buffer is the idiomatic equivalent.

    Args:
        buffer_size: The size of the buffer to allocate.
    """
    if not isinstance(buffer_size, int) or not (0 < buffer_size <= MAX_BUFFER_SIZE):
        print(f"Error: Invalid buffer size. Must be an integer between 1 and {MAX_BUFFER_SIZE}.", file=sys.stderr)
        return

    try:
        # Create a mutable byte array initialized with 'A's.
        buffer = bytearray(b'A' * buffer_size)
        
        print(f"Successfully allocated and overwrote a buffer of size {buffer_size}.")
        # Basic check to confirm the operation
        if not buffer or buffer[0] != ord('A') or buffer[-1] != ord('A'):
             print("Buffer content verification failed.", file=sys.stderr)
    except MemoryError:
        print(f"Error: MemoryError while allocating buffer of size {buffer_size}.", file=sys.stderr)

def main():
    """Main function with test cases."""
    print("--- Test Case 1: Valid size (16) ---")
    overwrite_buffer(16)

    print("\n--- Test Case 2: Edge case size (1) ---")
    overwrite_buffer(1)
    
    print(f"\n--- Test Case 3: Maximum valid size ({MAX_BUFFER_SIZE}) ---")
    overwrite_buffer(MAX_BUFFER_SIZE)

    print("\n--- Test Case 4: Invalid size (0) ---")
    overwrite_buffer(0)

    print("\n--- Test Case 5: Invalid size (too large) ---")
    overwrite_buffer(MAX_BUFFER_SIZE + 1)

if __name__ == "__main__":
    main()