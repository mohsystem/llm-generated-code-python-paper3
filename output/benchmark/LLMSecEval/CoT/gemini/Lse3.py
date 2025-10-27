def my_memcpy(dest: bytearray, src: bytes, n: int):
    """
    Copies n bytes from a source (bytes or bytearray) to a destination (bytearray).
    
    Args:
        dest: The destination bytearray.
        src: The source bytes or bytearray.
        n: The number of bytes to copy.
    """
    # Security Check: Validate types
    if not isinstance(dest, bytearray) or not isinstance(src, (bytes, bytearray)):
        print("Error: dest must be a bytearray and src must be bytes or bytearray.")
        return
    # Security Check: Ensure n is not negative
    if n < 0:
        print("Error: Number of bytes cannot be negative.")
        return
    # Security Check: Prevent buffer overflow by checking lengths.
    if n > len(src) or n > len(dest):
        print("Error: Buffer overflow attempt detected. Copy operation aborted.")
        return

    # Perform the byte-by-byte copy.
    for i in range(n):
        dest[i] = src[i]

def main():
    print("Python Tests:")

    # Test Case 1: Standard copy "Hello"
    src1 = b"Hello"
    dest1 = bytearray(10)
    print("\n--- Test 1: Standard copy ---")
    print(f"Copying {len(src1)} bytes from {src1}.")
    print(f"Destination buffer size: {len(dest1)}")
    my_memcpy(dest1, src1, len(src1))
    print(f"Destination after copy: {dest1.split(b'\0')[0].decode()}")

    # Test Case 2: Full buffer copy
    src2 = b"12345"
    dest2 = bytearray(5)
    print("\n--- Test 2: Full buffer copy ---")
    print(f"Copying {len(src2)} bytes from {src2}.")
    print(f"Destination buffer size: {len(dest2)}")
    my_memcpy(dest2, src2, len(src2))
    print(f"Destination after copy: {dest2.decode()}")

    # Test Case 3: Partial copy
    src3 = b"World"
    dest3 = bytearray(10)
    print("\n--- Test 3: Partial copy ---")
    print("Copying 3 bytes from 'World'.")
    my_memcpy(dest3, src3, 3)
    print(f"Destination after copy: {dest3.split(b'\0')[0].decode()}")

    # Test Case 4: Copy empty source
    src4 = b""
    dest4 = bytearray(b"XXXXX")
    print("\n--- Test 4: Copy empty source ---")
    print(f"Destination before: {dest4.decode()}")
    my_memcpy(dest4, src4, 0)  # Copy 0 bytes
    print(f"Destination after copy (should be unchanged): {dest4.decode()}")

    # Test Case 5: Array to array copy
    src5 = bytearray(b"ABCDE")
    dest5 = bytearray(5)
    print("\n--- Test 5: Array to array copy ---")
    my_memcpy(dest5, src5, len(src5))
    print(f"Destination after copy: {dest5.decode()}")

if __name__ == "__main__":
    main()