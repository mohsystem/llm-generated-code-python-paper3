import os
import shutil

def copy_file(source_path, dest_path):
    """
    Copies a source file to a destination file, handling exceptions.
    Args:
        source_path (str): The path to the source file.
        dest_path (str): The path to the destination file.
    """
    try:
        # Ensure the destination directory exists before writing
        dest_dir = os.path.dirname(dest_path)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
            
        with open(source_path, 'r') as reader:
            with open(dest_path, 'w') as writer:
                content = reader.read()
                writer.write(content)
        print(f"Success: File copied from {source_path} to {dest_path}")
        
    except FileNotFoundError:
        print(f"Error: Input file not found at '{source_path}'")
    except PermissionError:
        print(f"Error: Permission denied to read '{source_path}' or write to '{dest_path}'")
    except IsADirectoryError:
        print(f"Error: The source path '{source_path}' is a directory, not a regular file.")
    except IOError as e:
        # Catches a broad range of I/O related errors
        print(f"Error: An I/O error occurred: {e}")
    except Exception as e:
        # A general catch-all for any other unexpected errors
        print(f"Error: An unexpected error occurred: {e}")

if __name__ == "__main__":
    test_dir = "python_test_files"
    valid_input_file = os.path.join(test_dir, "input.txt")
    valid_output_file = os.path.join(test_dir, "output.txt")
    read_only_dir = os.path.join(test_dir, "read_only_dir")

    # Setup test environment
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    with open(valid_input_file, 'w') as f:
        f.write("This is a test file for Python.\n")
        f.write("It has multiple lines.\n")
    
    os.makedirs(read_only_dir)
    # Set directory to read-only (chmod 555: r-xr-xr-x)
    os.chmod(read_only_dir, 0o555)
    
    print("--- Running Python Test Cases ---")

    # Test Case 1: Successful file copy
    print("\n[Test Case 1: Successful Copy]")
    copy_file(valid_input_file, valid_output_file)

    # Test Case 2: Input file not found
    print("\n[Test Case 2: Input File Not Found]")
    copy_file(os.path.join(test_dir, "non_existent.txt"), valid_output_file)

    # Test Case 3: Read error (trying to read a directory)
    print("\n[Test Case 3: Read Error (Reading a directory)]")
    copy_file(test_dir, valid_output_file)

    # Test Case 4: Write error (permission denied)
    print("\n[Test Case 4: Write Error (Permission Denied)]")
    copy_file(valid_input_file, os.path.join(read_only_dir, "output.txt"))

    # Test Case 5: Write error (invalid path)
    # The function creates the parent dir, but this fails if part of the path is a file.
    print("\n[Test Case 5: Write Error (Invalid Path)]")
    copy_file(valid_input_file, os.path.join(valid_input_file, "output.txt"))

    # Cleanup
    os.chmod(read_only_dir, 0o755)
    shutil.rmtree(test_dir)
    print("\n--- Python Tests Complete ---")