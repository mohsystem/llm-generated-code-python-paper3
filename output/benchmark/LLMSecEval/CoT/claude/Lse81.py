
import sys

BUFFER_SIZE = 1024
READ_SIZE = 10

def allocate_buffer():
    return bytearray(BUFFER_SIZE)

def read_characters(buffer):
    if buffer is None or len(buffer) < READ_SIZE:
        return -1
    
    try:
        input_str = input()
        chars_to_read = min(READ_SIZE, len(input_str), len(buffer))
        
        for i in range(chars_to_read):
            buffer[i] = ord(input_str[i])
        
        return chars_to_read
    except Exception as e:
        print(f"Error reading input: {e}")
        return -1

def main():
    # Test case 1: Normal input
    print("Test 1 - Enter 10 characters:")
    buf1 = allocate_buffer()
    read1 = read_characters(buf1)
    print(f"Characters read: {read1}")
    
    # Test case 2: Less than 10 characters
    print("\\nTest 2 - Enter less than 10 characters:")
    buf2 = allocate_buffer()
    read2 = read_characters(buf2)
    print(f"Characters read: {read2}")
    
    # Test case 3: More than 10 characters
    print("\\nTest 3 - Enter more than 10 characters:")
    buf3 = allocate_buffer()
    read3 = read_characters(buf3)
    print(f"Characters read: {read3}")
    
    # Test case 4: Empty input
    print("\\nTest 4 - Press Enter without input:")
    buf4 = allocate_buffer()
    read4 = read_characters(buf4)
    print(f"Characters read: {read4}")
    
    # Test case 5: Special characters
    print("\\nTest 5 - Enter special characters:")
    buf5 = allocate_buffer()
    read5 = read_characters(buf5)
    print(f"Characters read: {read5}")

if __name__ == "__main__":
    main()
