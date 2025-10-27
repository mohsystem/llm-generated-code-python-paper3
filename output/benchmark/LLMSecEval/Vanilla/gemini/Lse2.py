def memory_copy(destination: bytearray, source: bytes, num_bytes: int):
    """
    Copies a number of bytes from a source to a destination.
    """
    if not isinstance(destination, bytearray) or not isinstance(source, (bytes, bytearray)):
        return

    # Determine the actual number of bytes to copy
    length_to_copy = min(num_bytes, len(source), len(destination))
    
    # Perform the copy using slicing
    destination[0:length_to_copy] = source[0:length_to_copy]


if __name__ == '__main__':
    # Test Case 1: Basic copy
    print("--- Test Case 1: Basic Copy ---")
    src1 = b"Hello World"
    dest1 = bytearray(15)
    print(f"Destination before copy: {dest1}")
    memory_copy(dest1, src1, 5)
    print(f"Destination after copy:  {dest1.decode(errors='ignore').strip()}")
    print()

    # Test Case 2: Partial copy
    print("--- Test Case 2: Partial Copy ---")
    src2 = b"Programming"
    dest2 = bytearray(15)
    print(f"Destination before copy: {dest2}")
    memory_copy(dest2, src2, 4)
    print(f"Destination after copy:  {dest2.decode(errors='ignore').strip()}")
    print()

    # Test Case 3: Overwriting existing data
    print("--- Test Case 3: Overwriting Existing Data ---")
    src3 = b"NewData"
    dest3 = bytearray(b"OldDataOldData")
    print(f"Destination before copy: {dest3.decode()}")
    memory_copy(dest3, src3, 7)
    print(f"Destination after copy:  {dest3.decode()}")
    print()

    # Test Case 4: Copying zero bytes
    print("--- Test Case 4: Copying Zero Bytes ---")
    src4 = b"Source"
    dest4 = bytearray(b"Destination")
    original_dest = dest4.copy()
    print(f"Destination before copy: {original_dest.decode()}")
    memory_copy(dest4, src4, 0)
    print(f"Destination after copy:  {dest4.decode()}")
    print(f"Unchanged: {original_dest == dest4}")
    print()

    # Test Case 5: Copying more bytes than source length
    print("--- Test Case 5: Copying More Bytes Than Source ---")
    src5 = b"Short"
    dest5 = bytearray(10)
    print(f"Destination before copy: {dest5}")
    memory_copy(dest5, src5, 10)  # Should only copy 5 bytes
    print(f"Destination after copy:  {dest5.decode(errors='ignore').strip()}")
    print(f"Destination after copy (bytes): {dest5}")
    print()