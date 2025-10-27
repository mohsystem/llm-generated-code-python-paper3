
def allocate_and_copy(data):
    if data is None:
        print("Error: Input data is None")
        return
    
    # Limit size to prevent excessive memory allocation
    MAX_SIZE = 1024
    if len(data) > MAX_SIZE:
        print("Error: Input data exceeds maximum size")
        return
    
    try:
        # Allocate first chunk (convert string to bytes)
        chunk1 = data.encode('utf-8')
        
        # Allocate second chunk with same size (create copy)
        chunk2 = bytearray(len(chunk1))
        
        # Safely copy contents
        chunk2[:] = chunk1
        
        # Print contents of second chunk
        print(f"Contents of second chunk: {chunk2.decode('utf-8')}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    # Test case 1: Normal string
    print("Test 1:")
    allocate_and_copy("Hello World")
    
    # Test case 2: Empty string
    print("\\nTest 2:")
    allocate_and_copy("")
    
    # Test case 3: String with special characters
    print("\\nTest 3:")
    allocate_and_copy("Test@123!#$")
    
    # Test case 4: None input
    print("\\nTest 4:")
    allocate_and_copy(None)
    
    # Test case 5: Unicode string
    print("\\nTest 5:")
    allocate_and_copy("Hello 世界")


if __name__ == "__main__":
    main()
