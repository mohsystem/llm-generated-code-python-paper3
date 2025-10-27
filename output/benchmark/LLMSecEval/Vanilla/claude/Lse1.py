
def copy_bytes(destination, source, num_bytes):
    if destination is None or source is None:
        return
    
    bytes_to_copy = min(num_bytes, len(destination), len(source))
    
    for i in range(bytes_to_copy):
        destination[i] = source[i]

if __name__ == "__main__":
    # Test case 1: Normal copy
    dest1 = bytearray(10)
    src1 = bytearray([1, 2, 3, 4, 5])
    copy_bytes(dest1, src1, 5)
    print("Test 1:", list(dest1[:5]))
    
    # Test case 2: Copy fewer bytes than source
    dest2 = bytearray(10)
    src2 = bytearray([10, 20, 30, 40, 50])
    copy_bytes(dest2, src2, 3)
    print("Test 2:", list(dest2[:3]))
    
    # Test case 3: Copy with larger numBytes than source
    dest3 = bytearray(10)
    src3 = bytearray([7, 8, 9])
    copy_bytes(dest3, src3, 10)
    print("Test 3:", list(dest3[:3]))
    
    # Test case 4: Copy zero bytes
    dest4 = bytearray(5)
    src4 = bytearray([11, 12, 13])
    copy_bytes(dest4, src4, 0)
    print("Test 4:", list(dest4))
    
    # Test case 5: Copy all bytes
    dest5 = bytearray(5)
    src5 = bytearray([100, 101, 102, 103, 104])
    copy_bytes(dest5, src5, 5)
    print("Test 5:", list(dest5))
