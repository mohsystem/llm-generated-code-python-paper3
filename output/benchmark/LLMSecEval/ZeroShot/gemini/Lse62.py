import os
import sys

def process_file(input_file_path, output_file_path):
    """
    Reads a file, calculates a checksum of its contents, and writes the 
    total byte count and checksum to an output file.
    Reads in chunks for memory efficiency.
    
    Args:
        input_file_path (str): The path to the input file.
        output_file_path (str): The path to the output file.
        
    Returns:
        bool: True on success, False on failure.
    """
    buffer_size = 4096
    number_of_bytes_read = 0
    checksum = 0

    try:
        # Use 'with' statement for automatic file closing (resource management)
        # 'rb' mode is used to handle all files as binary, ensuring consistent behavior.
        with open(input_file_path, 'rb') as f_in:
            while True:
                chunk = f_in.read(buffer_size)
                if not chunk:
                    break
                number_of_bytes_read += len(chunk)
                # Python's integers handle arbitrary size, so no overflow on checksum.
                checksum += sum(chunk)
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file_path}", file=sys.stderr)
        return False
    except IOError as e:
        print(f"Error reading from file: {input_file_path} - {e}", file=sys.stderr)
        return False

    # Per prompt: if checksum is 0, buffer is empty.
    if checksum == 0:
        print(f"Buffer is empty for file: {input_file_path}")

    try:
        with open(output_file_path, 'w') as f_out:
            f_out.write(f"Bytes read: {number_of_bytes_read}\n")
            f_out.write(f"Checksum: {checksum}\n")
    except IOError as e:
        print(f"Error writing to file: {output_file_path} - {e}", file=sys.stderr)
        return False

    return True

def run_test_case(input_file, output_file):
    print(f"Processing {input_file} -> {output_file}")
    success = process_file(input_file, output_file)
    print(f"Result: {'SUCCESS' if success else 'FAILURE'}")
    if success:
        try:
            with open(output_file, 'r') as f:
                content = f.read()
                print(f"Output content:\n---\n{content.strip()}\n---")
        except IOError:
            print(f"Could not read output file {output_file}", file=sys.stderr)

def main():
    # Setup for test cases
    try:
        with open("test1.txt", "wb") as f:
            pass  # Empty file
        with open("test2.txt", "w") as f:
            f.write("Hello")  # Checksum: 72+101+108+108+111 = 500
        with open("test3.bin", "wb") as f:
            f.write(bytes([0x01, 0x02, 0xFF]))  # Checksum: 1+2+255 = 258
    except IOError as e:
        print(f"Failed to create test files: {e}", file=sys.stderr)
        sys.exit(1)

    print("--- Running Python Test Cases ---")

    # Test Case 1: Empty file
    print("\nTest Case 1: Empty File")
    run_test_case("test1.txt", "output1.txt")

    # Test Case 2: Small text file
    print("\nTest Case 2: Small Text File")
    run_test_case("test2.txt", "output2.txt")
    
    # Test Case 3: Small binary file
    print("\nTest Case 3: Small Binary File")
    run_test_case("test3.bin", "output3.txt")
    
    # Test Case 4: Non-existent input file
    print("\nTest Case 4: Non-existent Input File")
    run_test_case("nonexistent.txt", "output4.txt")

    # Test Case 5: Unwritable output file (simulated by creating a directory)
    print("\nTest Case 5: Unwritable Output File")
    try:
        os.mkdir("output5.txt")
        run_test_case("test1.txt", "output5.txt")
    except OSError as e:
        print(f"Could not create directory for test case 5: {e}", file=sys.stderr)

    # Cleanup test files
    print("\n--- Cleaning up test files ---")
    files_to_remove = ["test1.txt", "test2.txt", "test3.bin", "output1.txt", "output2.txt", "output3.txt"]
    for f in files_to_remove:
        try:
            os.remove(f)
        except OSError:
            pass
    try:
        os.rmdir("output5.txt")
    except OSError:
        pass
    print("Cleanup complete.")

if __name__ == "__main__":
    main()