import os
import sys
from typing import NoReturn

def read_file_and_print(file_path: str) -> None:
    """
    Reads a file specified by the file path and prints its contents to the console.
    Handles potential IOErrors and ensures the file is closed properly.

    Args:
        file_path: The path to the file to be read.
    """
    # Rule #4 & #7: The file_path is untrusted input.
    # We avoid TOCTOU vulnerabilities by opening the file directly and handling exceptions.
    try:
        # Rule #8: The 'with' statement ensures the file is automatically closed.
        # Specify encoding for predictable behavior across platforms.
        with open(file_path, 'r', encoding='utf-8') as f:
            # Rule #1: Reading line by line is memory efficient.
            for line in f:
                sys.stdout.write(line)
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'", file=sys.stderr)
    except PermissionError:
        print(f"Error: Permission denied to read file '{file_path}'", file=sys.stderr)
    except IOError as e:
        print(f"An I/O error occurred while reading '{file_path}': {e}", file=sys.stderr)

def create_test_file(file_name: str, content: str) -> None:
    """Helper function to create a test file."""
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        print(f"Failed to create test file '{file_name}': {e}", file=sys.stderr)

def main() -> NoReturn:
    """Main function with test cases."""
    test_files = {
        "test1.txt": "Hello, World!",
        "test2.txt": "This is line 1.\nThis is line 2.",
        "test3.txt": "",
        "test4.txt": "UTF-8 characters: áéíóú ñ €"
    }

    for name, content in test_files.items():
        create_test_file(name, content)

    print("--- Test Case 1: File with a single line ---")
    read_file_and_print("test1.txt")
    print("\n--- Test Case 2: File with multiple lines ---")
    read_file_and_print("test2.txt")
    print("\n--- Test Case 3: Empty file ---")
    read_file_and_print("test3.txt")
    print("\n--- Test Case 4: File with UTF-8 characters ---")
    read_file_and_print("test4.txt")
    print("\n--- Test Case 5: Non-existent file ---")
    read_file_and_print("nonexistent.txt")

    # Cleanup
    for name in test_files:
        if os.path.exists(name):
            os.remove(name)

if __name__ == "__main__":
    main()