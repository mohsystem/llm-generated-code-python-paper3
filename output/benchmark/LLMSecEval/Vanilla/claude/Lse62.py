
def process_file(input_file_path, output_file_path):
    try:
        # Read file contents into buffer
        with open(input_file_path, 'rb') as f:
            buffer = f.read()
        
        bytes_read = len(buffer)
        
        # Calculate checksum
        checksum = sum(buffer)
        
        # Check if checksum is 0 (buffer is empty)
        if checksum == 0:
            print("Buffer is empty or checksum is 0")
        
        # Save results to output file
        with open(output_file_path, 'w') as f:
            f.write(f"Bytes Read: {bytes_read}\\n")
            f.write(f"Checksum: {checksum}\\n")
        
        return bytes_read, checksum
        
    except IOError as e:
        print(f"Error: {e}")
        return 0, 0

if __name__ == "__main__":
    # Test case 1: File with text content
    try:
        with open("test1.txt", 'w') as f:
            f.write("Hello World")
        bytes_read, checksum = process_file("test1.txt", "output1.txt")
        print(f"Test 1 - Bytes: {bytes_read}, Checksum: {checksum}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Empty file
    try:
        with open("test2.txt", 'w') as f:
            pass
        bytes_read, checksum = process_file("test2.txt", "output2.txt")
        print(f"Test 2 - Bytes: {bytes_read}, Checksum: {checksum}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: File with numbers
    try:
        with open("test3.txt", 'w') as f:
            f.write("1234567890")
        bytes_read, checksum = process_file("test3.txt", "output3.txt")
        print(f"Test 3 - Bytes: {bytes_read}, Checksum: {checksum}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: File with special characters
    try:
        with open("test4.txt", 'w') as f:
            f.write("!@#$%^&*()")
        bytes_read, checksum = process_file("test4.txt", "output4.txt")
        print(f"Test 4 - Bytes: {bytes_read}, Checksum: {checksum}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Larger text file
    try:
        with open("test5.txt", 'w') as f:
            f.write("The quick brown fox jumps over the lazy dog")
        bytes_read, checksum = process_file("test5.txt", "output5.txt")
        print(f"Test 5 - Bytes: {bytes_read}, Checksum: {checksum}")
    except Exception as e:
        print(f"Test 5 failed: {e}")
