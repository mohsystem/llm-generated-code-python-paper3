
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

def main():
    # Test case 1: Copy "Hello" to buffer
    buffer1 = bytearray(10)
    source1 = bytearray(b"Hello")
    copy_bytes(buffer1, source1, len(source1))
    print("Test 1:", buffer1[:len(source1)].decode())
    
    # Test case 2: Copy partial string
    buffer2 = bytearray(10)
    source2 = bytearray(b"Hello")
    copy_bytes(buffer2, source2, 3)
    print("Test 2:", buffer2[:3].decode())
    
    # Test case 3: Copy to exact size buffer
    buffer3 = bytearray(5)
    source3 = bytearray(b"Hello")
    copy_bytes(buffer3, source3, 5)
    print("Test 3:", buffer3.decode())
    
    # Test case 4: Copy empty string
    buffer4 = bytearray(10)
    source4 = bytearray(b"")
    copy_bytes(buffer4, source4, 0)
    print("Test 4: (empty)")
    
    # Test case 5: Copy another string
    buffer5 = bytearray(15)
    source5 = bytearray(b"World")
    copy_bytes(buffer5, source5, len(source5))
    print("Test 5:", buffer5[:len(source5)].decode())

if __name__ == "__main__":
    main()
