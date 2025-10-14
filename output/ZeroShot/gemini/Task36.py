import os
import sys

# Define a safe base directory for file operations.
SAFE_DIRECTORY = os.path.realpath("safe_dir")

def read_file_and_print(filename):
    """
    Securely reads a file and prints its contents to the console.
    The file is expected to be inside a pre-defined safe directory.
    """
    # Security Check 1: Basic validation. Filename should be a simple name, not a path.
    if filename is None or os.path.isabs(filename) or ".." in filename or os.path.sep in filename or (os.path.altsep and os.path.altsep in filename):
        print("Error: Invalid filename provided.", file=sys.stderr)
        return

    try:
        full_path = os.path.join(SAFE_DIRECTORY, filename)
        
        # Security Check 2: Ensure the resolved canonical path is within the safe directory.
        # This prevents path traversal attacks.
        real_path = os.path.realpath(full_path)
        if not real_path.startswith(SAFE_DIRECTORY):
            print("Error: Access denied. Path is outside the safe directory.", file=sys.stderr)
            return

        # Security Check 3: Ensure the path points to a regular file.
        if not os.path.isfile(real_path):
            print("Error: Path does not point to a regular file or file does not exist.", file=sys.stderr)
            return

        print(f"--- Reading file: {filename} ---")
        # Use a 'with' statement to ensure the file is closed automatically.
        with open(real_path, 'r', encoding='utf-8') as f:
            for line in f:
                print(line, end='')
        print(f"\n--- End of file: {filename} ---\n")

    except FileNotFoundError:
        print(f"Error: File not found: {filename}", file=sys.stderr)
    except PermissionError:
        print(f"Error: Permission denied for file: {filename}", file=sys.stderr)
    except Exception:
        print(f"An error occurred while reading the file: {filename}", file=sys.stderr)

def main():
    """Sets up a test environment and runs test cases."""
    try:
        os.makedirs(SAFE_DIRECTORY, exist_ok=True)
        with open(os.path.join(SAFE_DIRECTORY, "test1.txt"), "w") as f:
            f.write("This is the first test file.")
        with open(os.path.join(SAFE_DIRECTORY, "test2.txt"), "w") as f:
            f.write("This is the second test file.\nIt has multiple lines.")
        with open("insecure.txt", "w") as f:
            f.write("This file is outside the safe directory.")
        os.makedirs(os.path.join(SAFE_DIRECTORY, "subdir"), exist_ok=True)
        print(f"Setup complete. Safe directory is at: {SAFE_DIRECTORY}")
        print("Running tests...\n")
    except OSError as e:
        print(f"Failed to set up test environment: {e}", file=sys.stderr)
        return

    print("Test Case 1: Reading a valid file.")
    read_file_and_print("test1.txt")

    print("Test Case 2: Reading another valid file.")
    read_file_and_print("test2.txt")

    print("Test Case 3: Attempting to read a non-existent file.")
    read_file_and_print("nonexistent.txt")
    print()

    print("Test Case 4: Path traversal attempt.")
    read_file_and_print("../insecure.txt")
    print()

    print("Test Case 5: Attempting to read a directory.")
    read_file_and_print("subdir")
    print()

if __name__ == "__main__":
    main()