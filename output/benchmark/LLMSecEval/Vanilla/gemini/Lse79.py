import sys

def process_strings(input1, input2):
    """
    Allocates two 1024-byte buffers and copies up to 100 characters (bytes)
    from the input strings into them.
    """
    # Allocate first 1024-byte buffer, initialized to null bytes
    buf1 = bytearray(1024)
    # Encode string to bytes and copy up to 100 bytes
    input1_bytes = input1.encode('utf-8')
    len1_to_copy = min(len(input1_bytes), 100)
    buf1[:len1_to_copy] = input1_bytes[:len1_to_copy]

    # Allocate second 1024-byte buffer
    buf2 = bytearray(1024)
    # Encode string to bytes and copy up to 100 bytes
    input2_bytes = input2.encode('utf-8')
    len2_to_copy = min(len(input2_bytes), 100)
    buf2[:len2_to_copy] = input2_bytes[:len2_to_copy]
    
    # Find the first null byte to determine content length and decode for printing
    try:
        result1 = buf1[:buf1.index(0)].decode('utf-8')
    except ValueError: # No null byte found
        result1 = buf1.decode('utf-8', errors='ignore')

    try:
        result2 = buf2[:buf2.index(0)].decode('utf-8')
    except ValueError:
        result2 = buf2.decode('utf-8', errors='ignore')

    print(f'Buffer 1 content: "{result1}"')
    print(f'Buffer 2 content: "{result2}"')

def main():
    test_cases = [
        ("Hello World", "This is a test"),
        ("A short string", "A very very very very very very very very very very very very very very very very very very very long string that will be truncated."),
        ("", "An empty string for the first input."),
        ("Another test case with numbers 12345.", ""),
        ("Last test case! Using special characters: !@#$%^&*()", "And another one.")
    ]

    for i, (in1, in2) in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f'Input 1: "{in1}"')
        print(f'Input 2: "{in2}"')
        process_strings(in1, in2)
        print("---------------------\n")

if __name__ == "__main__":
    main()