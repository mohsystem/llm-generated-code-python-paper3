import sys
import os
import re
from typing import Optional

# Rule #1, #5: Validate filename format.
# Whitelist of allowed characters: alphanumeric, dot, underscore, hyphen. Length 1-255.
FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")

def read_file_content(filename: str) -> Optional[str]:
    """
    Validates a filename and reads its content if it is a regular, accessible file.

    Args:
        filename: The name of the file to read, must be in the current directory.

    Returns:
        The content of the file as a string, or None on error.
    """
    if not filename:
        print("Error: Filename cannot be empty.", file=sys.stderr)
        return None

    # Rule #1, #5: Validate filename to prevent path traversal and invalid characters.
    if not FILENAME_REGEX.match(filename):
        print(f"Error: Invalid filename '{filename}'. Only alphanumeric, '.', '_', '-' are allowed. No path separators.", file=sys.stderr)
        return None

    # The filename is now considered safe to use in path operations within the current directory.
    
    # Rule #5, #6: Check for existence and that it's a regular file.
    # TOCTOU vulnerability exists between these checks and open().
    if not os.path.exists(filename):
        print(f"Error: File does not exist: {filename}", file=sys.stderr)
        return None

    if not os.path.isfile(filename):
        print(f"Error: Path is not a regular file: {filename}", file=sys.stderr)
        return None

    try:
        # Rule #7: Handle potential exceptions during file I/O.
        # Rule #8: Use context manager for automatic resource management.
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except (IOError, UnicodeDecodeError, PermissionError) as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        return None

def main():
    """Main function to run test cases and process command-line arguments."""
    # --- Test Cases ---
    print("--- Running Test Cases ---")
    valid_file = "test1.txt"
    empty_file = "empty.txt"
    non_existent_file = "no_such_file.txt"
    directory_name = "test_dir"
    invalid_filename = "../test1.txt"

    # Setup test environment
    if not os.path.exists(directory_name):
        os.mkdir(directory_name)
    with open(valid_file, 'w', encoding='utf-8') as f:
        f.write("Hello, Python World!\n")
    with open(empty_file, 'w', encoding='utf-8') as f:
        pass

    try:
        # Test Case 1: Valid file
        print(f"\n1. Testing with a valid file ({valid_file}):")
        content = read_file_content(valid_file)
        if content is not None:
            print(f"Success. Content:\n{content.strip()}")
        else:
            print("Failed unexpectedly.", file=sys.stderr)

        # Test Case 2: Non-existent file
        print(f"\n2. Testing with a non-existent file ({non_existent_file}):")
        content = read_file_content(non_existent_file)
        if content is None:
            print("Success. Function returned None as expected.")
        else:
            print("Failed. Read content unexpectedly.", file=sys.stderr)

        # Test Case 3: Invalid filename (path traversal)
        print(f"\n3. Testing with an invalid filename ({invalid_filename}):")
        content = read_file_content(invalid_filename)
        if content is None:
            print("Success. Function returned None as expected.")
        else:
            print("Failed. Read content unexpectedly.", file=sys.stderr)

        # Test Case 4: A directory
        print(f"\n4. Testing with a directory ({directory_name}):")
        content = read_file_content(directory_name)
        if content is None:
            print("Success. Function returned None as expected.")
        else:
            print("Failed. Read content unexpectedly.", file=sys.stderr)

        # Test Case 5: An empty file
        print(f"\n5. Testing with an empty file ({empty_file}):")
        content = read_file_content(empty_file)
        if content is not None:
            print(f"Success. Content is empty: '{content.strip()}'")
        else:
            print("Failed unexpectedly.", file=sys.stderr)

    finally:
        # Cleanup test environment
        if os.path.exists(valid_file): os.remove(valid_file)
        if os.path.exists(empty_file): os.remove(empty_file)
        if os.path.exists(directory_name): os.rmdir(directory_name)

    print("\n--- End of Test Cases ---")

    # --- Main Program Logic ---
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <filename>", file=sys.stderr)
        sys.exit(1)

    filename = sys.argv[1]
    print(f"\nAttempting to read from command line argument: {filename}")
    content = read_file_content(filename)

    if content is not None:
        print("--- File Content ---")
        print(content, end="")
        print("--- End of Content ---")
    else:
        print("Could not read file.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()