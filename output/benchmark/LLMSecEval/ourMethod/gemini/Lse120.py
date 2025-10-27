import sys

def manage_and_copy_memory(initial_data: str):
    """
    Allocates two memory chunks (bytearrays), copies the content from the
    first to the second, and prints the second chunk's content.
    """
    if not isinstance(initial_data, str):
        print("Error: Initial data must be a string.", file=sys.stderr)
        return

    try:
        # 1. Allocate and populate the first chunk of memory (source)
        # using a mutable bytearray.
        source = bytearray(initial_data, 'utf-8')

        # 2. Allocate the second chunk of memory (destination).
        destination = bytearray(len(source))

        # 3. Copy the contents of the first chunk into the second chunk.
        # Slicing is a safe, bounds-checked operation in Python.
        destination[:] = source

        # 4. Print the contents of the second chunk.
        print(f"Copied data: \"{destination.decode('utf-8')}\"")

    except MemoryError:
        print("Error: Failed to allocate memory.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    print("--- Test Case 1: Standard string ---")
    manage_and_copy_memory("Hello, World!")
    
    print("\n--- Test Case 2: Empty string ---")
    manage_and_copy_memory("")

    print("\n--- Test Case 3: String with numbers and symbols ---")
    manage_and_copy_memory("123!@#$%^&*()_+")

    print("\n--- Test Case 4: Long string ---")
    manage_and_copy_memory(
        "This is a much longer string to test the memory allocation "
        "and copy for a slightly larger chunk of data."
    )

    print("\n--- Test Case 5: Non-string input (for error handling) ---")
    manage_and_copy_memory(None)