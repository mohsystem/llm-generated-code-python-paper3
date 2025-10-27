
import sys

def memory_allocation_method():
    # Allocate first buffer of 1024 bytes
    buf = bytearray(1024)
    
    # Read up to 100 characters from stdin into first buffer
    input1 = sys.stdin.readline().rstrip('\\n')
    len1 = min(len(input1), 100)
    for i in range(len1):
        buf[i] = ord(input1[i])
    
    # Allocate second buffer of 1024 bytes
    buf1 = bytearray(1024)
    
    # Read up to 100 characters from stdin into second buffer
    input2 = sys.stdin.readline().rstrip('\\n')
    len2 = min(len(input2), 100)
    for i in range(len2):
        buf1[i] = ord(input2[i])
    
    print(f"First buffer (first 100 chars): {buf[:len1].decode('utf-8', errors='ignore')}")
    print(f"Second buffer (first 100 chars): {buf1[:len2].decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    test_cases = [
        ("Hello World", "Python Programming"),
        ("This is a test string", "Another test string"),
        ("12345", "67890"),
        ("A" * 150, "B" * 150),
        ("", "")
    ]
    
    for i, (input1, input2) in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input 1: {input1[:50]}..." if len(input1) > 50 else f"Input 1: {input1}")
        print(f"Input 2: {input2[:50]}..." if len(input2) > 50 else f"Input 2: {input2}")
        
        # Simulate stdin
        import io
        sys.stdin = io.StringIO(f"{input1}\\n{input2}\\n")
        memory_allocation_method()
        print()
