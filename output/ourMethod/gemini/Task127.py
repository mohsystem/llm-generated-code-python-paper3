import os
import shutil
import tempfile
import pathlib
from typing import Optional

def copy_file_to_temp(base_dir_str: str, file_name_str: str) -> Optional[str]:
    """
    Reads a file from a base directory and writes its content to a new temporary file.
    This function is secured against path traversal attacks.

    Args:
        base_dir_str: The trusted base directory.
        file_name_str: The name of the file to be read (untrusted).

    Returns:
        The path to the temporary file, or None if an error occurred.
    """
    try:
        # Resolve the base directory to its absolute, canonical path
        base_dir = pathlib.Path(base_dir_str).resolve(strict=True)
        if not base_dir.is_dir():
            print(f"Error: Base path '{base_dir_str}' is not a directory.")
            return None

        # Prevent file names from containing path components
        if os.path.sep in file_name_str or (os.path.altsep and os.path.altsep in file_name_str):
            print("Error: File name cannot contain path separators.")
            return None

        # Construct and resolve the input file path
        input_file = (base_dir / file_name_str).resolve(strict=True)
        
        # Security check: Ensure the resolved input file path is within the base directory.
        if base_dir not in input_file.parents:
            print("Error: Path traversal attempt detected. Access denied.")
            return None

        # Security check: Ensure we are reading a regular file
        if not input_file.is_file():
            print(f"Error: '{input_file}' is not a regular file.")
            return None
            
        # Create a temporary file. delete=False to keep it after closing context.
        fd, temp_file_path = tempfile.mkstemp(prefix="temp-copy-", suffix=".tmp")
        os.close(fd) # mkstemp opens the file, we close it so shutil can use it.
        
        # Copy file content
        shutil.copyfile(input_file, temp_file_path)
        
        return temp_file_path

    except FileNotFoundError:
        print(f"Error: File not found at path '{base_dir_str}/{file_name_str}'.")
        return None
    except PermissionError:
        print(f"Error: Permission denied to read '{file_name_str}'.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def main():
    """Main function with test cases."""
    # Setup a temporary directory for tests
    with tempfile.TemporaryDirectory() as test_base_dir:
        try:
            valid_file_path = os.path.join(test_base_dir, "valid.txt")
            with open(valid_file_path, "w") as f:
                f.write("Hello, Python!")
            
            sub_dir_path = os.path.join(test_base_dir, "subdir")
            os.makedirs(sub_dir_path)

            print(f"Test environment set up in: {test_base_dir}")
            print("------------------------------------------")

            # Test Case 1: Valid file
            print("Test Case 1: Valid file 'valid.txt'")
            temp_path_1 = copy_file_to_temp(test_base_dir, "valid.txt")
            if temp_path_1:
                print(f"Success! Copied to: {temp_path_1}")
                os.remove(temp_path_1)
            else:
                print("Failed unexpectedly.")
            print()

            # Test Case 2: Non-existent file
            print("Test Case 2: Non-existent file 'nonexistent.txt'")
            temp_path_2 = copy_file_to_temp(test_base_dir, "nonexistent.txt")
            if not temp_path_2:
                print("Success! Operation failed as expected.")
            else:
                print(f"Failed! An unexpected temporary file was created: {temp_path_2}")
                os.remove(temp_path_2)
            print()

            # Test Case 3: Path traversal attempt
            print("Test Case 3: Path traversal attempt '../test.txt'")
            temp_path_3 = copy_file_to_temp(test_base_dir, os.path.join("..", "test.txt"))
            if not temp_path_3:
                print("Success! Path traversal blocked as expected.")
            else:
                print(f"Failed! Path traversal was successful: {temp_path_3}")
                os.remove(temp_path_3)
            print()

            # Test Case 4: Accessing a directory
            print("Test Case 4: Attempting to copy a directory 'subdir'")
            temp_path_4 = copy_file_to_temp(test_base_dir, "subdir")
            if not temp_path_4:
                print("Success! Directory access blocked as expected.")
            else:
                print(f"Failed! Directory was copied: {temp_path_4}")
                os.remove(temp_path_4)
            print()

            # Test Case 5: Invalid base directory
            print("Test Case 5: Using a non-existent base directory")
            non_existent_base_dir = os.path.join(test_base_dir, "nonexistent_dir")
            temp_path_5 = copy_file_to_temp(non_existent_base_dir, "valid.txt")
            if not temp_path_5:
                print("Success! Invalid base directory handled correctly.")
            else:
                print(f"Failed! An unexpected file was created: {temp_path_5}")
                os.remove(temp_path_5)
        
        except Exception as e:
            print(f"An error occurred during testing: {e}")

if __name__ == "__main__":
    main()