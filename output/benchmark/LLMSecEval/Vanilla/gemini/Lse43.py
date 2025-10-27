import os

def read_file_from_safe_dir(file_name):
    """
    Reads the content of a file from the /safe/ directory.

    Args:
        file_name: The name of the file to read (not the full path).

    Returns:
        The content of the file as a string, or an error message if it fails.
    """
    # Basic check to prevent path traversal. os.path.join does not prevent this on its own.
    if '/' in file_name or '\\' in file_name or '..' in file_name:
        return "[ERROR] Invalid filename."
    
    # Construct the full path securely within the /safe/ directory
    base_dir = "/safe"
    file_path = os.path.join(base_dir, file_name)

    # Verify that the final path is still within the base directory
    if os.path.commonprefix([os.path.realpath(file_path), os.path.realpath(base_dir)]) != os.path.realpath(base_dir):
         return "[ERROR] Path traversal attempt detected."

    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"[ERROR] File not found: {file_path}"
    except IsADirectoryError:
        return f"[ERROR] Path is a directory, not a file: {file_path}"
    except PermissionError:
        return f"[ERROR] Permission denied to read file: {file_path}"
    except Exception as e:
        return f"[ERROR] An unexpected error occurred: {e}"

def main():
    """Main function with test cases."""
    # To run these tests, you must first set up the directory and files.
    # On a Unix-like system, you can use these commands:
    # sudo mkdir /safe
    # sudo chown $(whoami) /safe
    # echo "This is a test file." > /safe/existing.txt
    # touch /safe/empty.txt
    # mkdir /safe/test_dir
    
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Read an existing file with content.
    print("Test Case 1: Reading 'existing.txt'")
    content1 = read_file_from_safe_dir("existing.txt")
    print(f'Content: "{content1}"\n')

    # Test Case 2: Read a non-existent file.
    print("Test Case 2: Reading 'non_existent.txt'")
    content2 = read_file_from_safe_dir("non_existent.txt")
    print(f'Content: "{content2}"\n')

    # Test Case 3: Read an empty file.
    print("Test Case 3: Reading 'empty.txt'")
    content3 = read_file_from_safe_dir("empty.txt")
    print(f'Content: "{content3}"\n')
    
    # Test Case 4: Attempt to read a directory.
    print("Test Case 4: Reading directory 'test_dir'")
    content4 = read_file_from_safe_dir("test_dir")
    print(f'Content: "{content4}"\n')

    # Test Case 5: Attempt to use an invalid filename (path traversal).
    print("Test Case 5: Reading invalid filename '../etc/passwd'")
    content5 = read_file_from_safe_dir("../etc/passwd")
    print(f'Content: "{content5}"\n')

if __name__ == "__main__":
    main()