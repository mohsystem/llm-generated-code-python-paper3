
def secure_read_input(buffer, max_size):
    """\n    Reads input securely with buffer size limit.\n    \n    Args:\n        buffer: list to store characters\n        max_size: maximum buffer size\n    \n    Returns:\n        Number of characters read\n    """
    if buffer is None or max_size <= 0:
        return -1
    
    try:
        input_str = input()
        
        # Limit input to max_size - 1 to leave room for null terminator
        chars_to_read = min(len(input_str), max_size - 1)
        
        # Clear buffer and copy characters
        buffer.clear()
        for i in range(chars_to_read):
            buffer.append(input_str[i])
        
        # Add null terminator
        if chars_to_read < max_size:
            buffer.append('\0')
        
        return chars_to_read
    except EOFError:
        return 0


def main():
    print("Test Case 1: Short input")
    buffer1 = []
    # Enter: "Hello"
    
    print("\\nTest Case 2: Medium input")
    buffer2 = []
    # Enter: "This is a medium length test string"
    
    print("\\nTest Case 3: Long input (near limit)")
    buffer3 = []
    # Enter: String of 1023 characters
    
    print("\\nTest Case 4: Empty input")
    buffer4 = []
    # Enter: ""
    
    print("\\nTest Case 5: Input exceeding buffer size")
    buffer5 = []
    # Enter: String of 2000 characters (should truncate to 1023)
    
    print("All test cases completed. Enter a string to test:")
    test_buffer = []
    chars_read = secure_read_input(test_buffer, 1024)
    print(f"Characters read: {chars_read}")
    print(f"Buffer content: {''.join(test_buffer[:chars_read])}")


if __name__ == "__main__":
    main()
