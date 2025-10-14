import subprocess
import re
import platform
import os
import sys

# Rule #1: Use a strict regex for allowed filename characters.
FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

def display_file_content(filename: str):
    """
    Displays the content of a file using a system command ('cat' or 'type').
    The filename is validated to prevent command injection and path traversal.

    :param filename: The name of the file to display. It must be in the current directory.
    """
    if not isinstance(filename, str) or not filename:
        print("Error: Filename must be a non-empty string.", file=sys.stderr)
        return

    # Rule #1 & #5: Validate filename format to prevent injection.
    if not FILENAME_PATTERN.match(filename):
        print("Error: Invalid filename format. Only alphanumeric characters, dots, underscores, and hyphens are allowed.", file=sys.stderr)
        return

    # Rule #5: An extra check to ensure no path separators are present.
    if '/' in filename or '\\' in filename:
        print("Error: Path traversal is not allowed. Please provide a simple filename.", file=sys.stderr)
        return
        
    # Rule #5 & #6: Check if it's a regular file and not a symlink before use.
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist.", file=sys.stderr)
        return
    if os.path.islink(filename) or not os.path.isfile(filename):
        print(f"Error: '{filename}' is not a regular file.", file=sys.stderr)
        return

    command = []
    try:
        # Rule #2: Use a list of arguments to avoid shell interpretation.
        # This is the primary defense against command injection.
        if platform.system() == "Windows":
            command = ["type", filename]
        else:
            command = ["cat", filename]
        
        # shell=False is the default and is crucial for security.
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            print(result.stdout, end='')
        else:
            print(f"Error executing command:\n{result.stderr}", file=sys.stderr, end='')
        
        print(f"\n--- Command finished with exit code: {result.returncode} ---")

    except FileNotFoundError:
        print(f"Error: The command '{command[0] if command else ''}' was not found.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)


def main():
    """Main function with test cases."""
    # Setup test environment
    is_windows = platform.system() == "Windows"
    try:
        with open("test_valid.txt", "w") as f:
            f.write("This is a valid test file.")
        os.makedirs("test_dir", exist_ok=True)
        if not is_windows: # Symlinks are tricky on Windows for non-admins
             if not os.path.exists("test_symlink.txt"):
                os.symlink("test_valid.txt", "test_symlink.txt")
    except Exception as e:
        print(f"Failed to set up test environment: {e}", file=sys.stderr)
        return

    print("--- Test Case 1: Valid file ---")
    display_file_content("test_valid.txt")
    print()

    print("--- Test Case 2: Non-existent file ---")
    display_file_content("non_existent_file.txt")
    print()

    print("--- Test Case 3: Invalid filename (command injection attempt) ---")
    display_file_content("test_valid.txt; ls")
    print()

    print("--- Test Case 4: Invalid filename (path traversal attempt) ---")
    display_file_content("../another_file.txt")
    print()

    print("--- Test Case 5: Directory instead of file ---")
    display_file_content("test_dir")
    print()

    if not is_windows:
        print("--- Test Case 6: Symbolic link ---")
        display_file_content("test_symlink.txt")
        print()

    # Cleanup
    try:
        os.remove("test_valid.txt")
        if os.path.exists("test_symlink.txt"):
            os.remove("test_symlink.txt")
        os.rmdir("test_dir")
    except Exception as e:
        print(f"Failed to clean up test environment: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()