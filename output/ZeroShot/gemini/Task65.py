import os
import re

def get_file_content(filename: str) -> str:
    """
    Securely reads the content of a file after validating the filename.
    The validation uses a whitelist to ensure the filename only contains safe characters
    and does not contain path traversal sequences or any path separators, 
    restricting access to the current directory.

    :param filename: The name of the file to read.
    :return: The content of the file as a string, or an error message if an issue occurs.
    """
    if not filename:
        return "Error: Filename cannot be empty."

    # Security Validation: Whitelist approach.
    # Allow only alphanumeric characters, dots, underscores, and hyphens.
    # This prevents directory traversal ('../') and absolute paths ('/').
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return "Error: Invalid filename format. Path separators and special characters are not allowed."

    try:
        # Construct path safely and resolve it to an absolute path
        current_dir = os.path.abspath(os.getcwd())
        file_path = os.path.abspath(os.path.join(current_dir, filename))

        # Security check: Ensure the resolved path is still within the intended directory.
        # This helps prevent symlink-based and other more complex traversal attacks.
        if not file_path.startswith(current_dir):
            return "Error: File access is restricted to the current directory."

        # Check for existence and type
        if not os.path.exists(file_path):
            return "Error: File does not exist."
        if not os.path.isfile(file_path):
            return "Error: Path does not point to a regular file."

        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()

    except PermissionError:
        return "Error: File is not readable (permission denied)."
    except IOError as e:
        return f"Error: An I/O error occurred: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    """Main function with test cases."""
    # --- Test Setup ---
    # Create a test file for the valid test case.
    try:
        with open("test1.txt", "w", encoding="utf-8") as f:
            f.write("This is a secure file.\n")
    except IOError as e:
        print(f"Warning: Could not set up test file 'test1.txt': {e}")

    test_cases = [
        "test1.txt",              # 1. Valid file
        "non_existent.txt",       # 2. Non-existent file
        "../other_dir/secret.txt",# 3. Path traversal attempt
        "safe_dir/test2.txt",     # 4. Filename with directory separator
        "/etc/passwd"             # 5. Absolute path attempt
    ]

    for i, filename in enumerate(test_cases, 1):
        print(f"--- Test Case {i}: \"{filename}\" ---")
        result = get_file_content(filename)
        print(f"Result:\n{result}\n")

if __name__ == "__main__":
    main()