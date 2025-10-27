
import os

class ChecksumResult:
    def __init__(self, bytes_read, checksum):
        self.bytes_read = bytes_read
        self.checksum = checksum

def calculate_checksum(buffer):
    checksum = 0
    for byte in buffer:
        checksum += byte
    return checksum

def save_results(output_path, bytes_read, checksum):
    with open(output_path, 'w') as f:
        f.write(f"Bytes Read: {bytes_read}\\n")
        f.write(f"Checksum: {checksum}\\n")

def process_file(input_path, output_path):
    try:
        # Read file contents into buffer
        with open(input_path, 'rb') as f:
            buffer = f.read()
        
        bytes_read = len(buffer)
        
        # Calculate checksum
        checksum = calculate_checksum(buffer)
        
        # Check if buffer is empty (checksum is 0)
        if checksum == 0:
            print("Buffer is empty or checksum is 0")
        
        # Save results to output file
        save_results(output_path, bytes_read, checksum)
        
        return ChecksumResult(bytes_read, checksum)
        
    except IOError as e:
        print(f"Error processing file: {e}")
        return ChecksumResult(0, 0)

if __name__ == "__main__":
    # Test case 1: File with some content
    with open("test1.txt", 'w') as f:
        f.write("Hello World")
    result1 = process_file("test1.txt", "output1.txt")
    print(f"Test 1 - Bytes: {result1.bytes_read}, Checksum: {result1.checksum}")
    
    # Test case 2: Empty file
    with open("test2.txt", 'w') as f:
        f.write("")
    result2 = process_file("test2.txt", "output2.txt")
    print(f"Test 2 - Bytes: {result2.bytes_read}, Checksum: {result2.checksum}")
    
    # Test case 3: File with numbers
    with open("test3.txt", 'w') as f:
        f.write("1234567890")
    result3 = process_file("test3.txt", "output3.txt")
    print(f"Test 3 - Bytes: {result3.bytes_read}, Checksum: {result3.checksum}")
    
    # Test case 4: File with special characters
    with open("test4.txt", 'w') as f:
        f.write("!@#$%^&*()")
    result4 = process_file("test4.txt", "output4.txt")
    print(f"Test 4 - Bytes: {result4.bytes_read}, Checksum: {result4.checksum}")
    
    # Test case 5: File with longer text
    with open("test5.txt", 'w') as f:
        f.write("The quick brown fox jumps over the lazy dog")
    result5 = process_file("test5.txt", "output5.txt")
    print(f"Test 5 - Bytes: {result5.bytes_read}, Checksum: {result5.checksum}")
