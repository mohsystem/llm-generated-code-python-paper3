
def allocate_and_read_buffers(input1, input2):
    """\n    Allocates two buffers and reads up to 100 characters into each.\n    Security: Validates input size to prevent overflow.\n    """
    # Security: Define buffer size constants
    BUFFER_SIZE = 1024
    READ_SIZE = 100
    
    # Allocate first buffer (simulated with bytearray in Python)
    buf = bytearray(BUFFER_SIZE)
    
    # Allocate second buffer
    buf1 = bytearray(BUFFER_SIZE)
    
    # Security: Validate and limit input size
    if input1 is not None:
        input1_bytes = input1.encode('utf-8')[:READ_SIZE]
        buf[:len(input1_bytes)] = input1_bytes
        result_buf = buf[:len(input1_bytes)].decode('utf-8')
    else:
        result_buf = ""
    
    if input2 is not None:
        input2_bytes = input2.encode('utf-8')[:READ_SIZE]
        buf1[:len(input2_bytes)] = input2_bytes
        result_buf1 = buf1[:len(input2_bytes)].decode('utf-8')
    else:
        result_buf1 = ""
    
    return result_buf, result_buf1


def main():
    # Test case 1: Normal input
    buf1, buf2 = allocate_and_read_buffers("Hello World", "Test Input")
    print(f"Test 1 - Buf1: {buf1}, Buf2: {buf2}")
    
    # Test case 2: Empty strings
    buf1, buf2 = allocate_and_read_buffers("", "")
    print(f"Test 2 - Buf1: '{buf1}', Buf2: '{buf2}'")
    
    # Test case 3: None inputs
    buf1, buf2 = allocate_and_read_buffers(None, None)
    print(f"Test 3 - Buf1: '{buf1}', Buf2: '{buf2}'")
    
    # Test case 4: Input exceeding 100 characters (should be truncated)
    long_string = "A" * 150
    buf1, buf2 = allocate_and_read_buffers(long_string, long_string)
    print(f"Test 4 - Buf1 length: {len(buf1)}, Buf2 length: {len(buf2)}")
    
    # Test case 5: Exactly 100 characters
    exact_string = "B" * 100
    buf1, buf2 = allocate_and_read_buffers(exact_string, exact_string)
    print(f"Test 5 - Buf1 length: {len(buf1)}, Buf2 length: {len(buf2)}")


if __name__ == "__main__":
    main()
