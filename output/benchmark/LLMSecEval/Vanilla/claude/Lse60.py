
import sys

def process_buffer(size):
    buffer = bytearray(size)
    
    print("Buffer contents:")
    for i in range(len(buffer)):
        print(buffer[i], end=" ")
        if (i + 1) % 20 == 0:
            print()
    print()

def main():
    # Test cases
    print("Test Case 1: Buffer size 10")
    process_buffer(10)
    
    print("\\nTest Case 2: Buffer size 25")
    process_buffer(25)
    
    print("\\nTest Case 3: Buffer size 50")
    process_buffer(50)
    
    print("\\nTest Case 4: Buffer size 5")
    process_buffer(5)
    
    print("\\nTest Case 5: Buffer size 100")
    process_buffer(100)
    
    # If command line argument is provided
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
            print(f"\\nCommand line argument: Buffer size {size}")
            process_buffer(size)
        except ValueError:
            print("Invalid buffer size argument", file=sys.stderr)

if __name__ == "__main__":
    main()
