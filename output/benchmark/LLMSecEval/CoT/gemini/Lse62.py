import os
import sys

def process_file_and_calculate_checksum(input_file_path, output_file_path):
    """
    Reads a file into a buffer, calculates a checksum, and saves the byte count
    and checksum to an output file.

    :param input_file_path: The path to the input file.
    :param output_file_path: The path to the output file where results will be saved.
    :return: True on success, False on failure.
    """
    try:
        # 1. Read the contents of the file into a buffer in binary mode.
        # The 'with' statement ensures the file is properly closed even if errors occur.
        with open(input_file_path, 'rb') as f_in:
            buffer = f_in.read()

        # 2. Calculate the checksum of the buffer.
        # Python's sum() on a bytes object directly sums the integer values (0-255) of each byte.
        checksum = sum(buffer)
        bytes_read = len(buffer)
        
        # Per instructions, if checksum is 0, the buffer is empty.
        if checksum == 0 and bytes_read > 0:
            print("Warning: Checksum is 0 for a non-empty file.", file=sys.stderr)

        # 3. Save the number of bytes read and the checksum to a file.
        result = f"Bytes: {bytes_read}, Checksum: {checksum}"
        
        # Ensure the output directory exists before writing
        output_dir = os.path.dirname(output_file_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(output_file_path, 'w') as f_out:
            f_out.write(result)
            
        return True

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file_path}'", file=sys.stderr)
        return False
    except IOError as e:
        print(f"An I/O error occurred: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

# Name of main class is not applicable in Python. We use the standard main execution block.
if __name__ == "__main__":
    # --- Test Cases ---

    # Test Case 1: A normal text file.
    print("--- Test Case 1: Normal File ---")
    input_file_1 = "test_input_1.txt"
    output_file_1 = "test_output_1.txt"
    with open(input_file_1, "w") as f:
        f.write("Hello")
    success_1 = process_file_and_calculate_checksum(input_file_1, output_file_1)
    print(f"Test 1 Success: {success_1}")
    if success_1:
        with open(output_file_1, "r") as f:
            print(f"Output: {f.read()}") # Expected: Bytes: 5, Checksum: 500
    os.remove(input_file_1)
    if os.path.exists(output_file_1): os.remove(output_file_1)
    print()

    # Test Case 2: An empty file.
    print("--- Test Case 2: Empty File ---")
    input_file_2 = "test_input_2.txt"
    output_file_2 = "test_output_2.txt"
    with open(input_file_2, "w") as f:
        pass
    success_2 = process_file_and_calculate_checksum(input_file_2, output_file_2)
    print(f"Test 2 Success: {success_2}")
    if success_2:
        with open(output_file_2, "r") as f:
            print(f"Output: {f.read()}") # Expected: Bytes: 0, Checksum: 0
    os.remove(input_file_2)
    if os.path.exists(output_file_2): os.remove(output_file_2)
    print()
    
    # Test Case 3: A binary file.
    print("--- Test Case 3: Binary File ---")
    input_file_3 = "test_input_3.bin"
    output_file_3 = "test_output_3.txt"
    # bytes 1, 128, 255
    with open(input_file_3, "wb") as f:
        f.write(b'\x01\x80\xff')
    success_3 = process_file_and_calculate_checksum(input_file_3, output_file_3)
    print(f"Test 3 Success: {success_3}")
    if success_3:
        with open(output_file_3, "r") as f:
            print(f"Output: {f.read()}") # Expected: Bytes: 3, Checksum: 384
    os.remove(input_file_3)
    if os.path.exists(output_file_3): os.remove(output_file_3)
    print()

    # Test Case 4: Non-existent input file.
    print("--- Test Case 4: Non-existent Input File ---")
    input_file_4 = "non_existent_file.txt"
    output_file_4 = "test_output_4.txt"
    success_4 = process_file_and_calculate_checksum(input_file_4, output_file_4)
    print(f"Test 4 Success: {success_4}") # Expected: False
    if os.path.exists(output_file_4): os.remove(output_file_4)
    print()

    # Test Case 5: Unwritable output file path (e.g., permission denied).
    # This is hard to simulate reliably across OSes. A common substitute is
    # trying to write to a path that is a directory, which should fail.
    print("--- Test Case 5: Invalid Output Path ---")
    input_file_5 = "test_input_5.txt"
    output_dir_5 = "test_output_dir_5"
    with open(input_file_5, "w") as f:
        f.write("test")
    os.makedirs(output_dir_5, exist_ok=True)
    # Trying to write a file where a directory with the same name exists
    success_5 = process_file_and_calculate_checksum(input_file_5, output_dir_5)
    print(f"Test 5 Success: {success_5}") # Expected: False
    os.remove(input_file_5)
    os.rmdir(output_dir_5)
    print()