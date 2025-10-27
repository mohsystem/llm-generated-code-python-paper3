
def copy_and_print(size, data):
    # Allocate two chunks of memory
    chunk1 = bytearray(size)
    chunk2 = bytearray(size)
    
    # Copy data into first chunk
    data_bytes = data.encode('utf-8')
    for i in range(min(len(data_bytes), size)):
        chunk1[i] = data_bytes[i]
    
    # Copy contents of first chunk into second chunk
    for i in range(size):
        chunk2[i] = chunk1[i]
    
    # Print contents of second chunk
    print(f"Contents of second chunk: {chunk2.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    # Test case 1
    print("Test Case 1:")
    copy_and_print(10, "Hello")
    
    # Test case 2
    print("\\nTest Case 2:")
    copy_and_print(15, "World")
    
    # Test case 3
    print("\\nTest Case 3:")
    copy_and_print(20, "Java Programming")
    
    # Test case 4
    print("\\nTest Case 4:")
    copy_and_print(5, "Test")
    
    # Test case 5
    print("\\nTest Case 5:")
    copy_and_print(30, "Memory Allocation Example")
