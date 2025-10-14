import os
import shutil
import tempfile

def copy_file_with_handling(source_path, dest_path):
    """
    Reads a file from source_path and writes its content to dest_path.
    Handles various file-related exceptions.

    Args:
        source_path (str): The path of the file to read.
        dest_path (str): The path of the file to write.
    
    Returns:
        bool: True on success, False on failure.
    """
    try:
        # The 'with' statement ensures files are automatically closed
        with open(source_path, 'rb') as f_source:
            with open(dest_path, 'wb') as f_dest:
                shutil.copyfileobj(f_source, f_dest)
        print(f"Successfully copied '{source_path}' to '{dest_path}'.")
        return True
    except FileNotFoundError:
        print(f"Error: Source file not found at '{source_path}'.")
    except PermissionError:
        print(f"Error: Permission denied to read '{source_path}' or write to '{dest_path}'.")
    except IsADirectoryError:
        print(f"Error: A file path points to a directory. Cannot perform operation.")
    except IOError as e:
        print(f"Error: An I/O error occurred. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}. Details: {e}")
    
    return False

def main():
    # Setup for test cases
    temp_dir = tempfile.gettempdir()
    source_file_path = os.path.join(temp_dir, "source.txt")
    dest_file_path = os.path.join(temp_dir, "destination.txt")
    non_existent_source = os.path.join(temp_dir, "non_existent_file.txt")
    write_protected_dir = os.path.join(temp_dir, "protected_dir")

    # Create dummy source file and directory for tests
    try:
        with open(source_file_path, 'w') as f:
            f.write("This is a test file.")
        if not os.path.exists(write_protected_dir):
            os.makedirs(write_protected_dir)
    except Exception as e:
        print(f"Failed to set up test cases: {e}")
        return

    print("--- Running Python Test Cases ---")

    # Test Case 1: Successful file copy
    print("\n[Test Case 1: Successful Copy]")
    copy_file_with_handling(source_file_path, dest_file_path)

    # Test Case 2: Source file does not exist
    print("\n[Test Case 2: Source File Not Found]")
    copy_file_with_handling(non_existent_source, dest_file_path)

    # Test Case 3: Reading a directory (simulates a read error)
    print("\n[Test Case 3: Read Error (source is a directory)]")
    copy_file_with_handling(temp_dir, dest_file_path)
    
    # Test Case 4: Destination is not writable (it's a directory)
    print("\n[Test Case 4: Write Error (destination is a directory)]")
    copy_file_with_handling(source_file_path, write_protected_dir)

    # Test Case 5: Invalid path (contains null byte)
    print("\n[Test Case 5: Invalid Argument (path with null byte)]")
    invalid_path = "invalid\0path.txt"
    copy_file_with_handling(source_file_path, invalid_path)

    # Cleanup
    if os.path.exists(source_file_path):
        os.remove(source_file_path)
    if os.path.exists(dest_file_path):
        os.remove(dest_file_path)
    if os.path.exists(write_protected_dir):
        shutil.rmtree(write_protected_dir)

if __name__ == "__main__":
    main()