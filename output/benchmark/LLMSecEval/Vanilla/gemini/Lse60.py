def allocate_and_print_buffer(size):
    """
    Allocates a buffer of a given size and prints its contents.
    A new bytearray is initialized with null bytes (zeros).
    """
    print(f"--- Testing with buffer size: {size} ---")
    if size < 0:
        print("Error: Size cannot be negative.")
        print()
        return

    try:
        # Allocate a buffer of the specified size.
        buffer = bytearray(size)
        
        # Print the contents of the buffer.
        # Convert to a list to display the numeric values.
        print(f"Allocated buffer contents: {list(buffer)}")
    except MemoryError:
        print(f"Error: Could not allocate buffer of size {size}. Out of memory.")
    
    print()

def main():
    """
    Main function to run 5 test cases.
    """
    test_sizes = [10, 0, 1, 8, 5]
    for size in test_sizes:
        allocate_and_print_buffer(size)

if __name__ == "__main__":
    main()