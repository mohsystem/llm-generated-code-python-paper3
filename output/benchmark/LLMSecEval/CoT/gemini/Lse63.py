import os

def process_file_and_get_checksum(input_path, output_path):
    """
    Reads a file into a buffer, calculates an 8-bit checksum,
    and writes the number of bytes read and the checksum to an output file.
    Args:
        input_path (str): The path to the input file.
        output_path (str): The path to the output file.
    Returns:
        bool: True on success, False on failure.
    """
    try:
        # 1. Read the contents of a file into a buffer.
        # Check for existence to provide a clear error message.
        if not os.path.exists(input_path):
            print(f"Error: Input file does not exist: {input_path}")
            return False

        with open(input_path, 'rb') as f_in:
            buffer = f_in.read()
        
        bytes_read = len(buffer)
        
        # 2. Calculate the checksum of the buffer.
        # sum() on a bytes object gives the sum of integer values of bytes.
        checksum = sum(buffer) % 256
        
        # 3. Checksum is 0 if buffer is empty.
        if bytes_read == 0:
            assert checksum == 0

        # 4. Save the number of bytes read and the checksum to another file.
        result = f"Bytes read: {bytes_read}, Checksum: {checksum}"
        with open(output_path, 'w') as f_out:
            f_out.write(result)
            
        return True
    except (IOError, OSError, PermissionError) as e:
        print(f"An error occurred: {e}")
        return False

# Main block with 5 test cases
if __name__ == "__main__":
    print("--- Python Test Cases ---")

    # Test Case 1: Standard text file
    try:
        with open("test1_in.txt", "w") as f:
            f.write("Hello, World!")
        process_file_and_get_checksum("test1_in.txt", "test1_out.txt")
        with open("test1_out.txt", "r") as f:
            print(f"Test Case 1 (Text): {f.read()}")
        os.remove("test1_in.txt")
        os.remove("test1_out.txt")
    except Exception as e:
        print(f"Test Case 1 failed: {e}")

    # Test Case 2: Binary data
    try:
        with open("test2_in.bin", "wb") as f:
            f.write(b'\xDE\xAD\xBE\xEF')
        process_file_and_get_checksum("test2_in.bin", "test2_out.txt")
        with open("test2_out.txt", "r") as f:
            print(f"Test Case 2 (Binary): {f.read()}")
        os.remove("test2_in.bin")
        os.remove("test2_out.txt")
    except Exception as e:
        print(f"Test Case 2 failed: {e}")

    # Test Case 3: Empty file
    try:
        open("test3_in.txt", "w").close() # Create empty file
        process_file_and_get_checksum("test3_in.txt", "test3_out.txt")
        with open("test3_out.txt", "r") as f:
            print(f"Test Case 3 (Empty): {f.read()}")
        os.remove("test3_in.txt")
        os.remove("test3_out.txt")
    except Exception as e:
        print(f"Test Case 3 failed: {e}")

    # Test Case 4: Non-existent file
    print("Test Case 4 (Not Found): ", end="")
    process_file_and_get_checksum("non_existent_file.txt", "test4_out.txt")

    # Test Case 5: File with content that results in a zero checksum
    try:
        with open("test5_in.bin", "wb") as f:
            f.write(b'\x01\xFF')
        process_file_and_get_checksum("test5_in.bin", "test5_out.txt")
        with open("test5_out.txt", "r") as f:
            print(f"Test Case 5 (Zero Checksum): {f.read()}")
        os.remove("test5_in.bin")
        os.remove("test5_out.txt")
    except Exception as e:
        print(f"Test Case 5 failed: {e}")
        
    print("--- Python Tests Complete ---\n")