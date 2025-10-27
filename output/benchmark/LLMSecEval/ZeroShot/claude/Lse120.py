
def copy_and_print(source):
    if source is None:
        print("Source is None")
        return
    
    # Allocate first chunk and store data
    first_chunk = str(source)
    
    # Allocate second chunk and copy data from first chunk
    second_chunk = str(first_chunk)
    
    # Print contents of second chunk
    print(second_chunk)

if __name__ == "__main__":
    # Test case 1: Normal string
    print("Test 1:")
    copy_and_print("Hello, World!")
    
    # Test case 2: Empty string
    print("\\nTest 2:")
    copy_and_print("")
    
    # Test case 3: String with special characters
    print("\\nTest 3:")
    copy_and_print("Special @#$% Characters!")
    
    # Test case 4: None input
    print("\\nTest 4:")
    copy_and_print(None)
    
    # Test case 5: Long string
    print("\\nTest 5:")
    copy_and_print("This is a longer string with multiple words and spaces")
