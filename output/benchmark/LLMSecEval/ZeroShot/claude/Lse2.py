
def copy_bytes(destination, source, num_bytes):
    if destination is None or source is None:
        raise ValueError("Destination and source cannot be None")
    if num_bytes < 0:
        raise ValueError("Number of bytes cannot be negative")
    if num_bytes > len(source):
        raise ValueError("Number of bytes exceeds source length")
    if num_bytes > len(destination):
        raise ValueError("Number of bytes exceeds destination capacity")
    
    for i in range(num_bytes):
        destination[i] = source[i]

if __name__ == "__main__":
    # Test case 1: Normal copy
    dest1 = bytearray(20)
    src1 = bytearray(b"Hello World")
    copy_bytes(dest1, src1, len(src1))
    print(f"Test 1: {dest1[:len(src1)].decode()}")
    
    # Test case 2: Partial copy
    dest2 = bytearray(10)
    src2 = bytearray(b"Testing")
    copy_bytes(dest2, src2, 4)
    print(f"Test 2: {dest2[:4].decode()}")
    
    # Test case 3: Copy with exact size
    dest3 = bytearray(5)
    src3 = bytearray(b"Exact")
    copy_bytes(dest3, src3, 5)
    print(f"Test 3: {dest3.decode()}")
    
    # Test case 4: Copy zero bytes
    dest4 = bytearray(10)
    src4 = bytearray(b"Zero")
    copy_bytes(dest4, src4, 0)
    print("Test 4: Empty copy successful")
    
    # Test case 5: Copy single byte
    dest5 = bytearray(10)
    src5 = bytearray(b"A")
    copy_bytes(dest5, src5, 1)
    print(f"Test 5: {dest5[:1].decode()}")
