
def copy_bytes(destination, source, num_bytes):
    if destination is None or source is None:
        raise ValueError("Destination and source cannot be None")
    
    if num_bytes < 0:
        raise ValueError("Number of bytes cannot be negative")
    
    if num_bytes > len(source):
        raise ValueError("Number of bytes exceeds source length")
    
    if num_bytes > len(destination):
        raise ValueError("Number of bytes exceeds destination length")
    
    for i in range(num_bytes):
        destination[i] = source[i]


if __name__ == "__main__":
    # Test case 1: Normal copy
    src1 = bytearray([1, 2, 3, 4, 5])
    dst1 = bytearray(5)
    copy_bytes(dst1, src1, 5)
    print(f"Test 1: {list(dst1)}")
    
    # Test case 2: Partial copy
    src2 = bytearray([10, 20, 30, 40, 50])
    dst2 = bytearray(5)
    copy_bytes(dst2, src2, 3)
    print(f"Test 2: {list(dst2)}")
    
    # Test case 3: Copy 0 bytes
    src3 = bytearray([1, 2, 3])
    dst3 = bytearray(3)
    copy_bytes(dst3, src3, 0)
    print(f"Test 3: {list(dst3)}")
    
    # Test case 4: Single byte copy
    src4 = bytearray([99])
    dst4 = bytearray(1)
    copy_bytes(dst4, src4, 1)
    print(f"Test 4: {list(dst4)}")
    
    # Test case 5: Larger array
    src5 = bytearray([11, 22, 33, 44, 55, 66, 77, 88])
    dst5 = bytearray(8)
    copy_bytes(dst5, src5, 8)
    print(f"Test 5: {list(dst5)}")
