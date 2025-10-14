
def reverse_string(input_str):
    if input_str is None:
        return None
    return input_str[::-1]

if __name__ == "__main__":
    # Test case 1: Normal string
    print("Test 1:", reverse_string("hello"))
    
    # Test case 2: String with spaces
    print("Test 2:", reverse_string("hello world"))
    
    # Test case 3: Empty string
    print("Test 3:", reverse_string(""))
    
    # Test case 4: Single character
    print("Test 4:", reverse_string("a"))
    
    # Test case 5: String with special characters
    print("Test 5:", reverse_string("Hello123!@#"))
