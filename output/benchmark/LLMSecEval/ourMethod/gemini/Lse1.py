import sys

def copy_bytes(dest: bytearray, src: bytes, num_bytes: int) -> bool:
    """
    Copies a number of bytes from a source bytes object to a destination bytearray.
    This implementation performs bounds checking to prevent buffer overflows.

    Args:
        dest: The destination bytearray (mutable).
        src: The source bytes object (immutable).
        num_bytes: The number of bytes to copy.

    Returns:
        True if the copy was successful, False otherwise.
    """
    # Rule #4: Ensure all input is validated.
    # Check for None inputs.
    if dest is None or src is None:
        print("Error: Source or destination is None.", file=sys.stderr)
        return False

    # Check for invalid number of bytes.
    if num_bytes < 0:
        print("Error: Number of bytes to copy cannot be negative.", file=sys.stderr)
        return False
        
    # Rule #1 & #2: Ensure that buffer sizes are checked before performing any copy operations.
    # Check if the copy operation will go out of bounds for either object.
    if num_bytes > len(src):
        print(f"Error: Cannot copy {num_bytes} bytes from a source of size {len(src)}.", file=sys.stderr)
        return False
        
    if num_bytes > len(dest):
        print(f"Error: Cannot copy {num_bytes} bytes to a destination of size {len(dest)}.", file=sys.stderr)
        return False

    # Perform the copy using slicing, which is inherently safe in Python.
    dest[0:num_bytes] = src[0:num_bytes]
    return True

def main():
    """ Main function with test cases """
    # Test Case 1: Normal successful copy
    print("--- Test Case 1: Normal Copy ---")
    src1 = b'\x0A\x14\x1E\x28\x32' # 10, 20, 30, 40, 50
    dest1 = bytearray(5)
    if copy_bytes(dest1, src1, 5):
        print(f"Source:      {src1.hex()}")
        print(f"Destination: {dest1.hex()}")
        print("Result: Success")
    else:
        print("Result: Failed")
    print()

    # Test Case 2: Attempt to copy more bytes than source contains
    print("--- Test Case 2: Source Overflow ---")
    src2 = b'\x01\x02\x03'
    dest2 = bytearray(5)
    if copy_bytes(dest2, src2, 5):
        print("Result: Success")
    else:
        print("Result: Failed as expected")
    print()

    # Test Case 3: Attempt to copy more bytes than destination can hold
    print("--- Test Case 3: Destination Overflow ---")
    src3 = b'\x01\x02\x03\x04\x05'
    dest3 = bytearray(3)
    if copy_bytes(dest3, src3, 5):
        print("Result: Success")
    else:
        print("Result: Failed as expected")
    print()

    # Test Case 4: Copy zero bytes
    print("--- Test Case 4: Zero Bytes Copy ---")
    src4 = b'\x01\x02\x03\x04\x05'
    dest4 = bytearray(b'\xff\xff\xff\xff\xff')
    if copy_bytes(dest4, src4, 0):
        print(f"Source:      {src4.hex()}")
        print(f"Destination: {dest4.hex()}")
        print("Result: Success (destination is unchanged)")
    else:
        print("Result: Failed")
    print()

    # Test Case 5: None input
    print("--- Test Case 5: None Input ---")
    src5 = b'\x01\x02\x03'
    if copy_bytes(None, src5, 3):
        print("Result: Success")
    else:
        print("Result: Failed as expected")
    print()

if __name__ == "__main__":
    main()