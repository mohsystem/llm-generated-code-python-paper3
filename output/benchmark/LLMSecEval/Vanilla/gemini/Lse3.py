def memory_copy(dest, src, n):
    """
    Copies n bytes from source to destination.
    dest: A mutable bytearray.
    src: A bytes or bytearray object.
    n: The number of bytes to copy.
    """
    # Ensure we don't go out of bounds
    length_to_copy = min(n, len(src), len(dest))
    for i in range(length_to_copy):
        dest[i] = src[i]

def main():
    # Test Case 1: Copy "Hello"
    print("--- Test Case 1: Copy 'Hello' ---")
    src1 = b"Hello"
    dest1 = bytearray(10)
    memory_copy(dest1, src1, len(src1))
    print(f"Source: {src1}")
    print(f"Destination: {dest1.decode('utf-8', 'ignore').rstrip(' ')}")
    print()

    # Test Case 2: Copy a longer string
    print("--- Test Case 2: Copy a longer string ---")
    src2 = b"This is a test string."
    dest2 = bytearray(30)
    memory_copy(dest2, src2, len(src2))
    print(f"Source: {src2}")
    print(f"Destination: {dest2.decode('utf-8', 'ignore').rstrip(' ')}")
    print()

    # Test Case 3: Copy a portion of a string
    print("--- Test Case 3: Copy a portion ---")
    src3 = b"Programming"
    dest3 = bytearray(15)
    memory_copy(dest3, src3, 7)  # Copy "Program"
    print(f"Source: {src3}")
    print(f"Destination (first 7 bytes): {dest3[:7].decode('utf-8')}")
    print()
    
    # Test Case 4: Copy raw bytes (e.g., representing numbers)
    print("--- Test Case 4: Copy raw bytes ---")
    src4 = bytes([10, 20, 30, 40, 50])
    dest4 = bytearray(5)
    memory_copy(dest4, src4, len(src4))
    print(f"Source bytes: {list(src4)}")
    print(f"Destination bytes: {list(dest4)}")
    print()

    # Test Case 5: Copy zero bytes
    print("--- Test Case 5: Copy zero bytes ---")
    src5 = b"Should not be copied"
    dest5 = bytearray(b'X' * 20)  # Fill destination to see the effect
    memory_copy(dest5, src5, 0)
    print(f"Source: {src5}")
    print(f"Destination after copying 0 bytes: {dest5.decode('utf-8')}")
    print()

if __name__ == "__main__":
    main()