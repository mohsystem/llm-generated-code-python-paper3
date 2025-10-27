
def secure_copy(destination, source, num_bytes):
    """\n    Securely copies num_bytes from source to destination\n    Returns True on success, False on failure\n    """
    # Input validation
    if destination is None or source is None:
        print("Error: None value provided", file=__import__('sys').stderr)
        return False
    
    if not isinstance(destination, (bytearray, list)) or not isinstance(source, (bytes, bytearray, list)):
        print("Error: Invalid data types", file=__import__('sys').stderr)
        return False
    
    if num_bytes < 0:
        print("Error: Negative byte count", file=__import__('sys').stderr)
        return False
    
    if num_bytes > len(source):
        print("Error: Copy size exceeds source length", file=__import__('sys').stderr)
        return False
    
    if num_bytes > len(destination):
        print("Error: Copy size exceeds destination capacity", file=__import__('sys').stderr)
        return False
    
    # Safe copy operation
    for i in range(num_bytes):
        destination[i] = source[i]
    
    return True

if __name__ == "__main__":
    # Test case 1: Normal copy
    dest1 = bytearray(20)
    src1 = b"Hello World"
    print("Test 1:", secure_copy(dest1, src1, len(src1)))
    print("Result:", dest1[:len(src1)].decode())
    
    # Test case 2: Partial copy
    dest2 = bytearray(10)
    src2 = b"Test"
    print("\\nTest 2:", secure_copy(dest2, src2, 4))
    print("Result:", dest2[:4].decode())
    
    # Test case 3: Buffer overflow prevention
    dest3 = bytearray(5)
    src3 = b"Too long message"
    print("\\nTest 3:", secure_copy(dest3, src3, len(src3)))
    
    # Test case 4: None source
    dest4 = bytearray(10)
    print("\\nTest 4:", secure_copy(dest4, None, 5))
    
    # Test case 5: Negative byte count
    dest5 = bytearray(10)
    src5 = b"Data"
    print("\\nTest 5:", secure_copy(dest5, src5, -1))
