
import sys

class MemoryBuffer:
    def __init__(self, size):
        self.size = size
        self.buffer = bytearray(size)
    
    def read_input(self, max_chars):
        try:
            data = sys.stdin.read(min(max_chars, self.size - 1))
            encoded_data = data.encode('utf-8')[:min(max_chars, self.size - 1)]
            self.buffer[:len(encoded_data)] = encoded_data
            return len(encoded_data)
        except Exception as e:
            print(f"Error reading input: {e}", file=sys.stderr)
            return 0
    
    def get_content(self):
        try:
            return self.buffer.decode('utf-8').rstrip('\\x00')
        except:
            return ""

def allocate_and_read_buffers():
    buf = MemoryBuffer(1024)
    buf.read_input(100)
    
    buf1 = MemoryBuffer(1024)
    buf1.read_input(100)
    
    print(f"Buffer 1: {buf.get_content()}")
    print(f"Buffer 2: {buf1.get_content()}")
    
    return buf, buf1

def main():
    print("Test cases for memory allocation and input reading:")
    
    try:
        print("\\nTest Case 1: Normal execution")
        allocate_and_read_buffers()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
