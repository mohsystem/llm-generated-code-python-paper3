import os

def process_file(input_file_path, output_file_path):
    """
    Reads the contents of a file into a buffer, calculates the checksum of the buffer,
    and saves the number of bytes read and the checksum to another file.
    """
    bytes_read = 0
    checksum = 0
    buffer = b''

    try:
        # Check if the file exists before attempting to open
        if os.path.exists(input_file_path):
            with open(input_file_path, 'rb') as f_in:
                buffer = f_in.read()
        
        bytes_read = len(buffer)
        checksum = sum(buffer)

        # If the buffer is empty, bytes_read is 0 and sum(b'') is 0.
        # This satisfies the condition "If the checksum is 0 the buffer is empty."

        # Save the number of bytes read and the checksum to the output file
        with open(output_file_path, 'w') as f_out:
            f_out.write(f"Bytes read: {bytes_read}\n")
            f_out.write(f"Checksum: {checksum}\n")

    except IOError as e:
        print(f"An I/O error occurred: {e}")
        try:
            with open(output_file_path, 'w') as f_out:
                f_out.write(f"Error processing file: {e}\n")
        except IOError as ex:
            print(f"Failed to write error to output file: {ex}")

def create_test_file(path, content):
    """Helper function to create a test file with specified content."""
    with open(path, 'wb') as f:
        f.write(content)

def print_output_file(path):
    """Helper function to read and print the content of an output file for verification."""
    try:
        with open(path, 'r') as f:
            print(f"--- Contents of {path} ---")
            print(f.read(), end='')
            print("------------------------------------")
    except IOError as e:
        print(f"Could not read output file {path}: {e}")

if __name__ == "__main__":
    # Test Case 1: A non-empty text file
    test1_in = "test1_in.txt"
    test1_out = "test1_out.txt"
    create_test_file(test1_in, b"Hello World!")
    process_file(test1_in, test1_out)
    print_output_file(test1_out)

    # Test Case 2: An empty file
    test2_in = "test2_in.txt"
    test2_out = "test2_out.txt"
    create_test_file(test2_in, b"")
    process_file(test2_in, test2_out)
    print_output_file(test2_out)

    # Test Case 3: A file with binary data
    test3_in = "test3_in.bin"
    test3_out = "test3_out.bin"
    binary_data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    create_test_file(test3_in, binary_data)
    process_file(test3_in, test3_out)
    print_output_file(test3_out)

    # Test Case 4: A file with a single byte
    test4_in = "test4_in.txt"
    test4_out = "test4_out.txt"
    create_test_file(test4_in, b"A")
    process_file(test4_in, test4_out)
    print_output_file(test4_out)

    # Test Case 5: A file that doesn't exist
    test5_in = "non_existent_file.txt"
    test5_out = "test5_out.txt"
    if os.path.exists(test5_in):
        os.remove(test5_in)
    process_file(test5_in, test5_out)
    print_output_file(test5_out)