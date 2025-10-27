
import sys

def scan_string(buffer, max_size):
    """\n    Reads a string from standard input safely.\n    \n    Args:\n        buffer: List to store characters\n        max_size: Maximum buffer size\n    \n    Returns:\n        Number of characters read, or -1 on error\n    """
    if buffer is None or max_size <= 0:
        return -1
    
    try:
        # Read line without newline
        input_str = sys.stdin.readline().rstrip('\\n')
        
        # Limit to max_size - 1 for null terminator
        chars_to_read = min(len(input_str), max_size - 1)
        
        # Clear buffer and copy characters
        buffer.clear()
        for i in range(chars_to_read):
            buffer.append(input_str[i])
        buffer.append('\0')
        
        return chars_to_read
    except Exception:
        return -1

def main():
    print("Test Case 1: Short string")
    buffer1 = []
    print("Enter input: ", end='')
    count1 = scan_string(buffer1, 1024)
    print(f"Characters read: {count1}")
    print(f"Buffer content: {''.join(buffer1[:-1])}")
    
    print("\\nTest Case 2: Empty string")
    buffer2 = []
    print("Enter input: ", end='')
    count2 = scan_string(buffer2, 1024)
    print(f"Characters read: {count2}")
    
    print("\\nTest Case 3: String with spaces")
    buffer3 = []
    print("Enter input: ", end='')
    count3 = scan_string(buffer3, 1024)
    print(f"Characters read: {count3}")
    print(f"Buffer content: {''.join(buffer3[:-1])}")
    
    print("\\nTest Case 4: Maximum length string")
    buffer4 = []
    print("Enter input: ", end='')
    count4 = scan_string(buffer4, 1024)
    print(f"Characters read: {count4}")
    
    print("\\nTest Case 5: Special characters")
    buffer5 = []
    print("Enter input: ", end='')
    count5 = scan_string(buffer5, 1024)
    print(f"Characters read: {count5}")
    print(f"Buffer content: {''.join(buffer5[:-1])}")

if __name__ == "__main__":
    main()
