
import os

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def process_file(input_path, output_path):
    """\n    Reads file contents, calculates checksum, and saves results.\n    Returns tuple: (bytes_read, checksum)\n    """
    if not input_path or not output_path:
        raise ValueError("File paths cannot be empty")
    
    bytes_read = 0
    checksum = 0
    
    try:
        # Validate file exists and is readable
        if not os.path.exists(input_path) or not os.path.isfile(input_path):
            raise IOError("Invalid input file")
        
        # Check file size
        file_size = os.path.getsize(input_path)
        if file_size > MAX_FILE_SIZE:
            raise IOError("File size exceeds maximum allowed size")
        
        # Read file contents
        with open(input_path, 'rb') as f:
            buffer = f.read()
            bytes_read = len(buffer)
            
            # Calculate checksum
            for byte in buffer:
                checksum = (checksum + byte) & 0xFFFFFFFF  # Prevent overflow
        
        # Write results to output file
        with open(output_path, 'w') as f:
            f.write(f"Bytes Read: {bytes_read}\\n")
            f.write(f"Checksum: {checksum}\\n")
            f.write(f"Buffer Empty: {checksum == 0}\\n")
        
    except IOError as e:
        print(f"Error processing file: {e}")
        return (0, 0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        return (0, 0)
    
    return (bytes_read, checksum)


if __name__ == "__main__":
    # Test case 1: Normal file with content
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello World")
        result1 = process_file("test1.txt", "output1.txt")
        print(f"Test 1 - Bytes: {result1[0]}, Checksum: {result1[1]}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Empty file
    try:
        with open("test2.txt", "w") as f:
            pass
        result2 = process_file("test2.txt", "output2.txt")
        print(f"Test 2 - Bytes: {result2[0]}, Checksum: {result2[1]}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: File with numbers
    try:
        with open("test3.txt", "w") as f:
            f.write("1234567890")
        result3 = process_file("test3.txt", "output3.txt")
        print(f"Test 3 - Bytes: {result3[0]}, Checksum: {result3[1]}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Binary content
    try:
        with open("test4.txt", "wb") as f:
            f.write(bytes([0x01, 0x02, 0x03, 0x04, 0x05]))
        result4 = process_file("test4.txt", "output4.txt")
        print(f"Test 4 - Bytes: {result4[0]}, Checksum: {result4[1]}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Non-existent file
    try:
        result5 = process_file("nonexistent.txt", "output5.txt")
        print(f"Test 5 - Bytes: {result5[0]}, Checksum: {result5[1]}")
    except Exception as e:
        print("Test 5 handled error correctly")
