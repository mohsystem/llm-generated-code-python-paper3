import os
import shutil
import tempfile
import stat
import uuid

def copy_file_to_temp(base_dir, file_name):
    """
    Securely reads a file from a specified base directory and writes it to a temporary location.
    Prevents path traversal attacks.

    :param base_dir: The trusted base directory from which to read files.
    :param file_name: The name of the file to read, relative to the base directory.
    :return: The path to the created temporary file, or None on failure.
    """
    if not file_name:
        print("Error: File name cannot be empty.")
        return None

    try:
        # Create absolute paths and resolve any symbolic links or '..'
        abs_base_dir = os.path.realpath(base_dir)
        source_path = os.path.realpath(os.path.join(abs_base_dir, file_name))

        # Security Check: Ensure the resolved path is still within the base directory.
        if not source_path.startswith(abs_base_dir):
            raise ValueError(f"Path traversal attempt detected for file: {file_name}")

        # Securely create a temporary file
        # Using a file object directly from tempfile
        with tempfile.NamedTemporaryFile(delete=False, prefix="temp_copy_", suffix=".tmp") as temp_f:
            temp_path = temp_f.name
        
        # Copy file content
        with open(source_path, 'rb') as src_f, open(temp_path, 'wb') as dest_f:
            shutil.copyfileobj(src_f, dest_f)

        print(f"Successfully copied '{source_path}' to '{temp_path}'")
        return temp_path

    except FileNotFoundError:
        print(f"Error: Source file not found: {os.path.join(base_dir, file_name)}")
    except PermissionError:
        print(f"Error: Permission denied when accessing: {os.path.join(base_dir, file_name)}")
    except ValueError as e:
        print(f"Error: {e}")
    except (IOError, OSError) as e:
        print(f"An I/O error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    return None

def main():
    # --- Setup Test Environment ---
    test_dir_name = "python_test_dir_" + str(uuid.uuid4())[:8]
    good_file_path = os.path.join(test_dir_name, "good_file.txt")
    empty_file_path = os.path.join(test_dir_name, "empty_file.txt")
    unreadable_file_path = os.path.join(test_dir_name, "unreadable.txt")
    
    try:
        os.makedirs(test_dir_name, exist_ok=True)
        with open(good_file_path, "w") as f:
            f.write("This is a test file.")
        open(empty_file_path, "w").close()
        open(unreadable_file_path, "w").close()
        # Make the file unreadable (for the owner)
        os.chmod(unreadable_file_path, stat.S_IWUSR)

        print("--- Running Test Cases ---")
        
        # Test Case 1: Happy path - valid file
        print("\n1. Testing with a valid file:")
        temp1 = copy_file_to_temp(test_dir_name, "good_file.txt")
        if temp1:
            os.remove(temp1)

        # Test Case 2: File not found
        print("\n2. Testing with a non-existent file:")
        copy_file_to_temp(test_dir_name, "non_existent_file.txt")

        # Test Case 3: Path traversal attack
        print("\n3. Testing path traversal attack:")
        copy_file_to_temp(test_dir_name, "../some_other_file.txt")

        # Test Case 4: Empty file
        print("\n4. Testing with an empty file:")
        temp4 = copy_file_to_temp(test_dir_name, "empty_file.txt")
        if temp4:
            os.remove(temp4)

        # Test Case 5: Permission denied (read)
        print("\n5. Testing with an unreadable file:")
        copy_file_to_temp(test_dir_name, "unreadable.txt")

        print("\n--- Test Cases Finished ---")

    except Exception as e:
        print(f"Failed to set up/run test environment: {e}")
    finally:
        # --- Cleanup Test Environment ---
        if os.path.exists(test_dir_name):
            shutil.rmtree(test_dir_name)
            print("\nTest environment cleaned up.")

if __name__ == "__main__":
    main()