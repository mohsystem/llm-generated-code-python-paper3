def demonstrate_memory_operations(initial_data: str):
    """
    Allocates two bytearrays, copies content from first to second,
    prints the second, "frees" the first, prints the second again,
    and finally "frees" the second.
    """
    print(f"--- Demonstrating with data: \"{initial_data}\" ---")
    
    # The data to be stored in the first chunk of memory.
    data_bytes = initial_data.encode('utf-8')
    size = len(data_bytes)
    
    # 1. Allocate two chunks of memory.
    # In Python, bytearray is a mutable sequence of bytes.
    first_chunk = bytearray(size)
    
    # Initialize the first chunk.
    first_chunk[:] = data_bytes
    
    # 2. Copy the contents of the first chunk into the second chunk.
    # Slicing creates a copy, which is a safe way to prevent buffer overflows.
    second_chunk = first_chunk[:]
    
    # 3. Print the contents of the second chunk.
    try:
        print(f"Content of second chunk after copy: {second_chunk.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"Content of second chunk after copy (raw): {second_chunk}")

    # 4. Free the memory allocated to the first chunk.
    # In Python, we can't explicitly free memory. We delete the reference,
    # and the garbage collector reclaims the memory.
    del first_chunk
    print("First chunk freed (reference deleted).")

    # 5. Print the contents of the second chunk again.
    # The content remains because the second chunk is a separate memory area.
    try:
        print(f"Content of second chunk after freeing first: {second_chunk.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"Content of second chunk after freeing first (raw): {second_chunk}")

    # 6. Free the memory allocated to the second chunk.
    del second_chunk
    print("Second chunk freed (reference deleted).")
    print("-------------------------------------------------")


if __name__ == "__main__":
    # 5 Test Cases
    demonstrate_memory_operations("Test case 1: Hello, Python!")
    demonstrate_memory_operations("Test case 2: A different string.")
    demonstrate_memory_operations("Test case 3: Short")
    demonstrate_memory_operations("Test case 4: A much longer string to test allocation.")
    demonstrate_memory_operations("Test case 5: Final test case with symbols!@#$%")