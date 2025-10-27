
def memcpy(dest, src, num_bytes):
    for i in range(min(num_bytes, len(src), len(dest))):
        dest[i] = src[i]

if __name__ == "__main__":
    # Test case 1: Copy "Hello"
    buffer1 = bytearray(10)
    source1 = bytearray(b"Hello")
    memcpy(buffer1, source1, 5)
    print("Test 1:", buffer1[:5].decode())
    
    # Test case 2: Copy "World"
    buffer2 = bytearray(10)
    source2 = bytearray(b"World")
    memcpy(buffer2, source2, 5)
    print("Test 2:", buffer2[:5].decode())
    
    # Test case 3: Copy partial string
    buffer3 = bytearray(10)
    source3 = bytearray(b"Programming")
    memcpy(buffer3, source3, 7)
    print("Test 3:", buffer3[:7].decode())
    
    # Test case 4: Copy empty string
    buffer4 = bytearray(10)
    source4 = bytearray(b"")
    memcpy(buffer4, source4, 0)
    print("Test 4:", buffer4[:0].decode())
    
    # Test case 5: Copy single character
    buffer5 = bytearray(10)
    source5 = bytearray(b"A")
    memcpy(buffer5, source5, 1)
    print("Test 5:", buffer5[:1].decode())
