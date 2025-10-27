
import sys

BUFFER_SIZE = 1024
READ_SIZE = 10

def allocate_buffer():
    return bytearray(BUFFER_SIZE)

def read_characters(buf):
    if buf is None or len(buf) < READ_SIZE:
        return -1
    
    try:
        chars_read = 0
        for i in range(READ_SIZE):
            char = sys.stdin.read(1)
            if not char:
                break
            buf[i] = ord(char)
            chars_read += 1
        return chars_read
    except Exception:
        return -1

def main():
    print("Test Case 1:")
    buffer1 = allocate_buffer()
    print(f"Buffer allocated with size: {len(buffer1)}")
    
    print("\\nTest Case 2:")
    buffer2 = allocate_buffer()
    print("Enter 10 characters: ")
    read_count = read_characters(buffer2)
    print(f"Characters read: {read_count}")
    
    print("\\nTest Case 3: Reading into buffer")
    buffer3 = allocate_buffer()
    for i in range(READ_SIZE):
        buffer3[i] = ord('A') + i
    print("Pre-filled buffer with test data")
    
    print("\\nTest Case 4: Check buffer bounds")
    buffer4 = allocate_buffer()
    print(f"Buffer can safely hold {READ_SIZE} characters: {len(buffer4) >= READ_SIZE}")
    
    print("\\nTest Case 5: Null buffer check")
    result = read_characters(None)
    print(f"Reading into null buffer returns: {result}")

if __name__ == "__main__":
    main()
