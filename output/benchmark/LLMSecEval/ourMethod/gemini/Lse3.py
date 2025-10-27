import sys

def custom_memcpy(dest: bytearray, src: bytes, n: int):
    """
    Copies n bytes from a source bytes/bytearray to a destination bytearray.

    Args:
        dest: The destination bytearray (mutable).
        src: The source bytes or bytearray.
        n: The number of bytes to copy. Must be non-negative.
    
    Returns:
        None. Modifies dest in place.
    """
    # Rule #4: Input validation
    if not isinstance(dest, bytearray):
        print("Error: Destination must be a mutable bytearray.", file=sys.stderr)
        return
    if not isinstance(src, (bytes, bytearray)):
        print("Error: Source must be bytes or bytearray.", file=sys.stderr)
        return
    
    # Rule #1, #2: Ensure that buffer sizes are checked before copy operations.
    if n < 0:
        print("Error: Number of bytes to copy cannot be negative.", file=sys.stderr)
        return
    if len(src) < n:
        print(f"Error: Source buffer (size {len(src)}) is smaller than n ({n}).", file=sys.stderr)
        return
    if len(dest) < n:
        print(f"Error: Destination buffer (size {len(dest)}) is not large enough for n ({n}).", file=sys.stderr)
        return
        
    # Python's slicing is bounds-safe and handles the copy efficiently.
    # This copies the first 'n' bytes of 'src' to the first 'n' bytes of 'dest'.
    dest[0:n] = src[0:n]

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")

    # Test Case 1: Copy "Hello"
    print("\n--- Test Case 1: Copy 'Hello' ---")
    src1_str = "Hello"
    src1 = src1_str.encode('utf-8')
    dest1 = bytearray(10)
    bytes_to_copy1 = len(src1)
    print(f"Source: {src1}")
    print(f"Destination (before): {dest1}")
    custom_memcpy(dest1, src1, bytes_to_copy1)
    print(f"Destination (after):  {dest1}")
    print(f"Copied part as string: \"{dest1[:bytes_to_copy1].decode('utf-8')}\"")

    # Test Case 2: Copy an empty source (0 bytes)
    print("\n--- Test Case 2: Copy an empty source (0 bytes) ---")
    src2 = b""
    dest2 = bytearray(10)
    print(f"Destination (before): {dest2}")
    custom_memcpy(dest2, src2, 0)
    print(f"Destination (after):  {dest2}")
    
    # Test Case 3: Copy part of a longer string
    print("\n--- Test Case 3: Copy part of a string ---")
    src3 = b"World12345"
    dest3 = bytearray(5)
    print(f"Source: {src3}")
    custom_memcpy(dest3, src3, 5) # Copy "World"
    print(f"Copied part as string: \"{dest3.decode('utf-8')}\"")

    # Test Case 4: Destination buffer too small (error case)
    print("\n--- Test Case 4: Destination buffer too small ---")
    src4 = b"This is too long"
    dest4 = bytearray(5)
    custom_memcpy(dest4, src4, len(src4)) # Should print an error

    # Test Case 5: Copy from one buffer to another
    print("\n--- Test Case 5: Copy from buffer to buffer ---")
    src5 = bytearray([10, 20, 30, 40, 50])
    dest5 = bytearray(5)
    print(f"Source: {src5}")
    print(f"Destination (before): {dest5}")
    custom_memcpy(dest5, src5, len(src5))
    print(f"Destination (after):  {dest5}")
    print(f"Arrays are equal: {src5 == dest5}")

if __name__ == "__main__":
    main()