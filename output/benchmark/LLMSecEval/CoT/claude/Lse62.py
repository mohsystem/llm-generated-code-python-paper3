
import os
from pathlib import Path

class ChecksumResult:
    def __init__(self, bytes_read, checksum):
        self.bytes_read = bytes_read
        self.checksum = checksum

MAX_BUFFER_SIZE = 1024 * 1024  # 1MB limit

def calculate_checksum(buffer):
    """Calculate checksum of buffer"""
    checksum = 0
    for byte in buffer:
        checksum += byte
    return checksum

def process_file(input_file_path, output_file_path):
    """Read file, calculate checksum, and save results"""
    if not input_file_path or not output_file_path:
        raise ValueError("File paths cannot be None or empty")
    
    try:
        # Validate and sanitize file paths
        in_path = Path(input_file_path).resolve()
        out_path = Path(output_file_path).resolve()
        
        # Check if input file exists
        if not in_path.exists():
            raise FileNotFoundError(f"Input file does not exist: {input_file_path}")
        
        # Check file size
        file_size = in_path.stat().st_size
        if file_size > MAX_BUFFER_SIZE:
            raise IOError(f"File too large. Maximum size: {MAX_BUFFER_SIZE}")
        
        # Read file into buffer
        with open(in_path, 'rb') as f:
            buffer = f.read()
        
        bytes_read = len(buffer)
        
        # Calculate checksum
        checksum = calculate_checksum(buffer)
        
        # Save results to output file
        with open(out_path, 'w') as f:
            f.write(f"Bytes Read: {bytes_read}\\n")
            f.write(f"Checksum: {checksum}\\n")
            if checksum == 0:
                f.write("Status: Buffer is empty or checksum is zero\\n")
        
        return ChecksumResult(bytes_read, checksum)
        
    except Exception as e:
        print(f"Error processing file: {e}")
        return ChecksumResult(0, 0)

def create_test_file(filename, content):
    """Helper function to create test files"""
    try:
        with open(filename, 'w') as f:
            f.write(content)
    except Exception as e:
        print(f"Error creating test file: {e}")

def main():
    # Test case 1: Normal file
    create_test_file("test1.txt", "Hello World")
    process_file("test1.txt", "output1.txt")
    
    # Test case 2: Empty file
    create_test_file("test2.txt", "")
    process_file("test2.txt", "output2.txt")
    
    # Test case 3: File with numbers
    create_test_file("test3.txt", "1234567890")
    process_file("test3.txt", "output3.txt")
    
    # Test case 4: Binary-like content
    create_test_file("test4.txt", "\\0\\0\\0\\0")
    process_file("test4.txt", "output4.txt")
    
    # Test case 5: Larger text
    create_test_file("test5.txt", "The quick brown fox jumps over the lazy dog")
    process_file("test5.txt", "output5.txt")
    
    print("All test cases executed. Check output files.")

if __name__ == "__main__":
    main()
