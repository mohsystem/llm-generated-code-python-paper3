import os
import shutil

def read_file_from_safe_directory(filename):
    """
    Reads a file from the 'safe' directory, preventing path traversal.
    :param filename: The name of the file to read.
    :return: The content of the file as a string, or an error message.
    """
    # Use a relative path for the safe directory for testing purposes.
    safe_dir = os.path.abspath('safe')

    # Basic sanitization
    if not filename or '..' in filename or os.path.isabs(filename):
        return "Error: Invalid filename (contains traversal characters or is absolute)."
        
    requested_path = os.path.abspath(os.path.join(safe_dir, filename))
    
    # Security check: Ensure the resolved path is a sub-path of the safe directory.
    # The os.sep at the end is crucial to prevent reading sibling directories like 'safe-etc'
    if not requested_path.startswith(safe_dir + os.sep) and requested_path != safe_dir:
        return "Error: Directory traversal attempt detected."

    if not os.path.exists(requested_path) or not os.path.isfile(requested_path):
        return "Error: File not found or is not a regular file."

    try:
        with open(requested_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: Could not read file. {e}"

def main():
    """Main function to run test cases."""
    safe_dir_path = 'safe'
    
    # Setup for test cases
    if os.path.exists(safe_dir_path):
        shutil.rmtree(safe_dir_path)
    os.makedirs(safe_dir_path)
    
    try:
        with open(os.path.join(safe_dir_path, 'test1.txt'), 'w', encoding='utf-8') as f:
            f.write('This is test file 1.')
        with open(os.path.join(safe_dir_path, 'another_file.log'), 'w', encoding='utf-8') as f:
            f.write('Log entry.')
        print("Test environment set up.")

        # Test cases
        test_files = [
            "test1.txt",              # 1. Valid file
            "another_file.log",       # 2. Another valid file
            "nonexistent.txt",        # 3. Non-existent file
            "../secret.txt",          # 4. Directory traversal attempt
            "../../etc/passwd"        # 5. More complex traversal attempt
        ]

        print("\n--- Running Test Cases ---")
        for i, filename in enumerate(test_files, 1):
            print(f"Test Case {i}: Requesting '{filename}'")
            content = read_file_from_safe_directory(filename)
            print(f"Result: {content}")
            print("----------------------------")

    finally:
        # Cleanup
        if os.path.exists(safe_dir_path):
            shutil.rmtree(safe_dir_path)
            print("\nTest environment cleaned up.")

if __name__ == "__main__":
    main()