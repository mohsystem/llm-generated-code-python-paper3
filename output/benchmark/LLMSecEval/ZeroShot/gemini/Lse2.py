def secure_copy(dest: bytearray, src: bytes, num_bytes: int) -> bool:
    """
    Securely copies a specified number of bytes from a source to a destination.
    The function prevents type errors, negative copy sizes, and buffer overflows.

    :param dest: The destination bytearray (must be mutable).
    :param src: The source bytes or bytearray.
    :param num_bytes: The number of bytes to copy.
    :return: True if the copy was successful, False otherwise.
    """
    # 1. Check for valid types
    if not isinstance(dest, bytearray):
        print("Error: Destination must be a mutable bytearray.")
        return False
    if not isinstance(src, (bytes, bytearray)):
        print("Error: Source must be bytes or bytearray.")
        return False

    # 2. Check for invalid size
    if num_bytes < 0:
        print("Error: Number of bytes to copy cannot be negative.")
        return False
        
    # 3. Check for buffer overflow on destination
    if num_bytes > len(dest):
        print("Error: Copy would result in a buffer overflow on the destination.")
        return False

    # 4. Check for buffer over-read on source
    if num_bytes > len(src):
        print("Error: Attempting to read past the end of the source buffer.")
        return False
        
    # Perform the copy using slicing, which is inherently safe in Python
    dest[:num_bytes] = src[:num_bytes]
    return True

if __name__ == "__main__":
    # Test Case 1: Normal successful copy
    print("--- Test Case 1: Normal Copy ---")
    src1 = b"Hello World"
    dest1 = bytearray(20)
    result1 = secure_copy(dest1, src1, 11)
    print(f"Result: {'Success' if result1 else 'Failure'}")
    if result1: print(f"Destination: \"{dest1[:11].decode()}\"")
    print()

    # Test Case 2: Boundary case (full buffer)
    print("--- Test Case 2: Full Buffer Copy ---")
    src2 = b"Test"
    dest2 = bytearray(4)
    result2 = secure_copy(dest2, src2, 4)
    print(f"Result: {'Success' if result2 else 'Failure'}")
    if result2: print(f"Destination: \"{dest2.decode()}\"")
    print()

    # Test Case 3: Destination buffer overflow attempt
    print("--- Test Case 3: Destination Overflow Attempt ---")
    src3 = b"This string is too long"
    dest3 = bytearray(b'XXXXX')
    dest3_original = dest3[:] 
    result3 = secure_copy(dest3, src3, len(src3))
    print(f"Result: {'Success' if result3 else 'Failure'}")
    print(f"Destination unchanged: {dest3 == dest3_original}")
    print()

    # Test Case 4: Source buffer over-read attempt
    print("--- Test Case 4: Source Over-read Attempt ---")
    src4 = b"short"
    dest4 = bytearray(20)
    dest4_original = dest4[:]
    result4 = secure_copy(dest4, src4, 10)
    print(f"Result: {'Success' if result4 else 'Failure'}")
    print(f"Destination unchanged: {dest4 == dest4_original}")
    print()

    # Test Case 5: Invalid input type
    print("--- Test Case 5: Invalid Input Type ---")
    src5 = "not bytes" # This is a string, not bytes
    dest5 = bytearray(10)
    result5 = secure_copy(dest5, src5, len(src5))
    print(f"Result (invalid source type): {'Success' if result5 else 'Failure'}")
    dest5_invalid = "not bytearray"
    src5_valid = b"valid"
    result5 = secure_copy(dest5_invalid, src5_valid, len(src5_valid))
    print(f"Result (invalid dest type): {'Success' if result5 else 'Failure'}")
    print()