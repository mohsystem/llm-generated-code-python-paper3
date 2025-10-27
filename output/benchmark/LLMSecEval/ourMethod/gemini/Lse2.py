import sys

def copy_bytes(dest: bytearray, src: bytes, n: int) -> bool:
    """
    Copies a number of bytes from a source to a destination.
    This implementation includes boundary checks to prevent buffer overflows.

    Args:
        dest: The destination bytearray.
        src: The source bytes object.
        n: The number of bytes to copy.
    
    Returns:
        True if the copy was successful, False otherwise.
    """
    # Rule #4: Input validation
    if not isinstance(dest, bytearray):
        print("Error: Destination must be a bytearray.", file=sys.stderr)
        return False
    if not isinstance(src, bytes):
        print("Error: Source must be a bytes object.", file=sys.stderr)
        return False
    if n < 0:
        print("Error: Number of bytes to copy cannot be negative.", file=sys.stderr)
        return False
    if n == 0:
        return True # Nothing to copy

    # Rules #1, #2: Ensure copy operations adhere to buffer boundaries.
    if n > len(src):
        print("Error: Attempting to read past the source buffer.", file=sys.stderr)
        return False
    if n > len(dest):
        print("Error: Destination buffer is too small.", file=sys.stderr)
        return False
    
    # Python's slice assignment is safe and handles this correctly.
    dest[:n] = src[:n]
    return True

def main():
    """Main function with test cases."""
    # Test Case 1: Normal successful copy
    print("--- Test Case 1: Normal Copy ---")
    src1 = b"Hello, Python!"
    dest1 = bytearray(50)
    n1 = len(src1)
    print(f"Attempting to copy {n1} bytes.")
    if copy_bytes(dest1, src1, n1):
        print("Copy successful.")
        print(f"Destination: {dest1[:n1].decode('utf-8')}")
    else:
        print("Copy failed.")
    print()

    # Test Case 2: Destination buffer too small
    print("--- Test Case 2: Destination Too Small ---")
    src2 = b"This message is too long for the destination"
    dest2 = bytearray(10)
    n2 = len(src2)
    print(f"Attempting to copy {n2} bytes into a 10-byte buffer.")
    if copy_bytes(dest2, src2, n2):
        print("Copy successful.")
    else:
        print("Copy failed as expected.")
    print()
    
    # Test Case 3: Source read out of bounds
    print("--- Test Case 3: Source Read Out of Bounds ---")
    src3 = b"short"
    dest3 = bytearray(20)
    n3 = 10  # Try to copy 10 bytes from a 5-byte source
    print(f"Attempting to copy {n3} bytes from a 5-byte source.")
    if copy_bytes(dest3, src3, n3):
        print("Copy successful.")
    else:
        print("Copy failed as expected.")
    print()

    # Test Case 4: Copy zero bytes
    print("--- Test Case 4: Zero Bytes Copy ---")
    src4 = b"some data"
    dest4 = bytearray(20)
    original_dest4 = dest4[:]
    n4 = 0
    print(f"Attempting to copy {n4} bytes.")
    if copy_bytes(dest4, src4, n4):
        print("Copy successful.")
        if dest4 == original_dest4:
            print("Destination buffer remains unchanged as expected.")
        else:
            print("Error: Destination buffer was modified.")
    else:
        print("Copy failed.")
    print()

    # Test Case 5: Exact size copy
    print("--- Test Case 5: Exact Size Copy ---")
    src5 = b"exact fit"
    n5 = len(src5)
    dest5 = bytearray(n5)
    print(f"Attempting to copy {n5} bytes into a {n5}-byte buffer.")
    if copy_bytes(dest5, src5, n5):
        print("Copy successful.")
        print(f"Destination: {dest5.decode('utf-8')}")
    else:
        print("Copy failed.")
    print()

if __name__ == "__main__":
    main()