
def secure_copy(dest, src, num_bytes):
    """\n    Securely copies bytes from source to destination with bounds checking\n    :param dest: destination bytearray\n    :param src: source bytes/bytearray\n    :param num_bytes: number of bytes to copy\n    :return: True if successful, False otherwise\n    """
    # Null/None checks
    if dest is None or src is None:
        print("Error: None buffer provided")
        return False
    
    # Validate num_bytes is non-negative
    if num_bytes < 0:
        print("Error: Negative byte count")
        return False
    
    # Check if source has enough bytes
    if num_bytes > len(src):
        print("Error: Source buffer too small")
        return False
    
    # Check if destination has enough space
    if num_bytes > len(dest):
        print("Error: Destination buffer too small")
        return False
    
    # Perform the copy
    for i in range(num_bytes):
        dest[i] = src[i]
    
    return True


def main():
    print("=== Test Case 1: Copy 'Hello' ===")
    dest1 = bytearray(10)
    src1 = b"Hello"
    if secure_copy(dest1, src1, len(src1)):
        print(f"Result: {dest1[:len(src1)].decode()}")
    
    print("\\n=== Test Case 2: Buffer too small ===")
    dest2 = bytearray(3)
    src2 = b"Hello"
    secure_copy(dest2, src2, len(src2))
    
    print("\\n=== Test Case 3: Zero bytes ===")
    dest3 = bytearray(10)
    src3 = b"Test"
    if secure_copy(dest3, src3, 0):
        print("Result: Successfully copied 0 bytes")
    
    print("\\n=== Test Case 4: None source ===")
    dest4 = bytearray(10)
    secure_copy(dest4, None, 5)
    
    print("\\n=== Test Case 5: Exact size match ===")
    dest5 = bytearray(5)
    src5 = b"World"
    if secure_copy(dest5, src5, len(src5)):
        print(f"Result: {dest5.decode()}")


if __name__ == "__main__":
    main()
