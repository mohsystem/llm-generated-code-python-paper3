
def copy_bytes(destination, source, num_bytes):
    for i in range(min(num_bytes, len(source), len(destination))):
        destination[i] = source[i]

if __name__ == "__main__":
    # Test case 1: Normal copy
    dest1 = bytearray(20)
    src1 = bytearray(b"Hello World")
    copy_bytes(dest1, src1, len(src1))
    print("Test 1:", dest1.decode('utf-8').rstrip('\\x00'))
    
    # Test case 2: Copy fewer bytes than source
    dest2 = bytearray(20)
    src2 = bytearray(b"Hello World")
    copy_bytes(dest2, src2, 5)
    print("Test 2:", dest2.decode('utf-8').rstrip('\\x00'))
    
    # Test case 3: Empty source
    dest3 = bytearray(20)
    src3 = bytearray(b"")
    copy_bytes(dest3, src3, 0)
    print("Test 3:", dest3.decode('utf-8').rstrip('\\x00'))
    
    # Test case 4: Copy with exact buffer size
    dest4 = bytearray(5)
    src4 = bytearray(b"12345")
    copy_bytes(dest4, src4, 5)
    print("Test 4:", dest4.decode('utf-8'))
    
    # Test case 5: Larger numBytes than source
    dest5 = bytearray(20)
    src5 = bytearray(b"Test")
    copy_bytes(dest5, src5, 10)
    print("Test 5:", dest5.decode('utf-8').rstrip('\\x00'))
