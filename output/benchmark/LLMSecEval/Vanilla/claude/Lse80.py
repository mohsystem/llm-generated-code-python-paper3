
def read_string(max_size=1024):
    try:
        input_str = input()
        chars_to_read = min(len(input_str), max_size - 1)
        buffer = input_str[:chars_to_read]
        return chars_to_read, buffer
    except EOFError:
        return 0, ""

if __name__ == "__main__":
    # Test case 1: Normal input
    print("Test 1 - Enter a string:")
    count1, string1 = read_string(1024)
    print(f"Characters read: {count1}")
    print(f"String: {string1}")
    
    # Test case 2: Empty input
    print("\\nTest 2 - Enter empty string:")
    count2, string2 = read_string(1024)
    print(f"Characters read: {count2}")
    
    # Test case 3: Short string
    print("\\nTest 3 - Enter 'Hello':")
    count3, string3 = read_string(1024)
    print(f"Characters read: {count3}")
    print(f"String: {string3}")
    
    # Test case 4: Long string
    print("\\nTest 4 - Enter a long string:")
    count4, string4 = read_string(1024)
    print(f"Characters read: {count4}")
    print(f"String: {string4}")
    
    # Test case 5: String with spaces
    print("\\nTest 5 - Enter 'Hello World':")
    count5, string5 = read_string(1024)
    print(f"Characters read: {count5}")
    print(f"String: {string5}")
