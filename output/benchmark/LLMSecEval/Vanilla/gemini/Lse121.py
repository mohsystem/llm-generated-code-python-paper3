import sys

def demonstrate_memory_operations(data_string):
    """
    Demonstrates memory allocation, copy, and freeing operations.
    """
    print(f"--- Running test with data: \"{data_string}\" ---")

    # 1. Allocate two chunks of memory.
    # We use bytearray which is a mutable sequence of bytes.
    chunk1 = bytearray(data_string, 'utf-8')
    chunk2 = bytearray(len(chunk1))
    print("Step 1: Two chunks allocated.")

    # 2. Copy the contents of the first chunk into the second chunk.
    chunk2[:] = chunk1
    print("Step 2: Contents of chunk1 copied to chunk2.")

    # 3. Print the contents of the second chunk.
    print(f"Step 3: Contents of chunk2 after copy: {chunk2.decode('utf-8')}")

    # 4. Free the memory allocated to the first chunk.
    # In Python, 'del' decrements the reference count.
    # The garbage collector reclaims memory when the count is zero.
    del chunk1
    print("Step 4: chunk1 has been freed (reference deleted).")

    # 5. Print the contents of the second chunk again.
    # The contents should be unchanged.
    print(f"Step 5: Contents of chunk2 after freeing chunk1: {chunk2.decode('utf-8')}")

    # 6. Free the memory allocated to the second chunk.
    del chunk2
    print("Step 6: chunk2 has been freed (reference deleted).")
    print("--- Test finished ---\n")

def main():
    """ Main function with 5 test cases """
    demonstrate_memory_operations("Hello World")
    demonstrate_memory_operations("Python Test Case")
    demonstrate_memory_operations("12345")
    demonstrate_memory_operations("Another piece of data.")
    demonstrate_memory_operations("") # Empty string test

if __name__ == "__main__":
    main()