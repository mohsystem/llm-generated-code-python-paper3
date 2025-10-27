import os
import sys

# Define a reasonable maximum file size to prevent DoS attacks (e.g., 100 MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

def process_file(input_path: str, output_path: str) -> bool:
    """
    Reads a file, calculates a checksum, and writes the results to another file.

    Args:
        input_path: The path to the input file.
        output_path: The path to the output file.

    Returns:
        True on success, False on failure.
    """
    # 1. Validate input path
    if not os.path.exists(input_path) or not os.access(input_path, os.R_OK):
        print(f"Error: Input file does not exist or is not readable: {input_path}", file=sys.stderr)
        return False

    try:
        # 2. Securely check file size before reading
        file_size = os.path.getsize(input_path)
        if file_size > MAX_FILE_SIZE:
            print(f"Error: Input file is too large: {file_size} bytes. Max allowed: {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False

        # 3. Read file contents into a buffer using a context manager for safety
        with open(input_path, 'rb') as f_in:
            buffer = f_in.read()
        
        bytes_read = len(buffer)
        
        # 4. Calculate checksum
        # Python's integers handle arbitrary size, so overflow isn't an issue.
        checksum = sum(buffer)

        # The prompt's logic: "If the checksum is 0 then the buffer is empty."
        if bytes_read == 0:
            print(f"Info: Buffer is empty for file {input_path}")
        
        # 5. Save the results to the output file
        # Ensure parent directory exists for the output file
        output_dir = os.path.dirname(output_path)
        if output_dir:
            # Check if we need to create the directory
            if not os.path.exists(output_dir):
                # This check prevents us from trying to create a dir for the "unwritable output" test
                # In a real scenario, you might want to create it: os.makedirs(output_dir, exist_ok=True)
                print(f"Error: Output directory does not exist: {output_dir}", file=sys.stderr)
                return False

        with open(output_path, 'w') as f_out:
            f_out.write(f"Bytes read: {bytes_read}\n")
            f_out.write(f"Checksum: {checksum}\n")

    except (IOError, OSError, PermissionError) as e:
        print(f"Error: Failed to process file '{input_path}': {e}", file=sys.stderr)
        return False
        
    return True

def main():
    """ Main function with 5 test cases """
    print("--- Running Python Test Cases ---")

    # Test Case 1: Empty file
    empty_in, empty_out = "test_empty_in.txt", "test_empty_out.txt"
    with open(empty_in, 'wb') as f: pass
    print("Test 1: Empty File")
    run_test("Test 1", empty_in, empty_out, True)

    # Test Case 2: ASCII text file
    ascii_in, ascii_out = "test_ascii_in.txt", "test_ascii_out.txt"
    with open(ascii_in, 'wb') as f: f.write(b"Hello World!")
    print("Test 2: ASCII File")
    run_test("Test 2", ascii_in, ascii_out, True)

    # Test Case 3: Binary file
    binary_in, binary_out = "test_binary_in.txt", "test_binary_out.txt"
    with open(binary_in, 'wb') as f: f.write(bytes([0x01, 0x02, 0x00, 0xFF, 0xFE]))
    print("Test 3: Binary File")
    run_test("Test 3", binary_in, binary_out, True)

    # Test Case 4: Non-existent input file
    non_existent_in, non_existent_out = "non_existent_file.txt", "test_no_input_out.txt"
    print("Test 4: Non-existent Input File")
    run_test("Test 4", non_existent_in, non_existent_out, False)
    
    # Test Case 5: Unwritable output file (invalid path)
    good_in = ascii_in # Re-use valid input
    unwritable_out = "non_existent_dir/output.txt"
    print("Test 5: Unwritable Output Path")
    run_test("Test 5", good_in, unwritable_out, False)

    # Cleanup
    cleanup_test_files([
        empty_in, empty_out, ascii_in, ascii_out, 
        binary_in, binary_out, non_existent_out
    ])
    print("--- Python Test Cases Finished ---\n")

def run_test(test_name, in_path, out_path, expected):
    result = process_file(in_path, out_path)
    if result == expected:
        print(f"  {test_name}: PASSED")
    else:
        print(f"  {test_name}: FAILED (Expected {expected}, got {result})")

def cleanup_test_files(files):
    for f in files:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass # Ignore cleanup errors

if __name__ == "__main__":
    main()