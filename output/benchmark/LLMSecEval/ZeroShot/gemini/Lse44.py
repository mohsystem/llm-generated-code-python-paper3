import os
import shutil

# The base directory from which files can be read.
# Using a relative path for easier testing without root permissions.
SAFE_DIRECTORY = "safe"

def read_file_from_safe_directory(filename: str) -> str:
    """
    Securely reads a file from a designated 'safe' directory.
    It prevents directory traversal attacks by sanitizing the filename and
    ensuring the resolved canonical path is within the safe directory.

    Args:
        filename: The name of the file to read. Must not contain path components.

    Returns:
        The content of the file as a string, or an error message.
    """
    # Validation 1: Sanitize filename by taking only the final component.
    # This effectively strips any directory information like '../' or '/'.
    sanitized_filename = os.path.basename(filename)
    if not sanitized_filename or sanitized_filename != filename:
        return "Error: Invalid filename. It must not contain path separators."

    try:
        # Get the canonical path of the safe directory. os.path.realpath resolves symlinks.
        base_dir = os.path.realpath(SAFE_DIRECTORY)
        requested_path = os.path.join(base_dir, sanitized_filename)

        # Validation 2: Get the canonical path of the requested file.
        real_requested_path = os.path.realpath(requested_path)
        
        # The core security check: ensure the resolved path is still inside the base directory.
        # We check that it starts with the base path and is not the base path itself.
        if not real_requested_path.startswith(os.path.join(base_dir, '')):
            return "Error: Directory traversal attempt detected."
            
        # Ensure it is a regular file.
        if not os.path.isfile(real_requested_path):
            return "Error: File not found or is not a regular file."

        with open(real_requested_path, 'r', encoding='utf-8') as f:
            return f.read()

    except FileNotFoundError:
        return "Error: File not found."
    except IOError as e:
        return f"Error: Cannot read file. {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred. {e}"

def main():
    """Sets up a test environment, runs test cases, and cleans up."""
    # --- Test Environment Setup ---
    if os.path.exists(SAFE_DIRECTORY):
        shutil.rmtree(SAFE_DIRECTORY)
    os.makedirs(SAFE_DIRECTORY)
    with open(os.path.join(SAFE_DIRECTORY, "document1.txt"), "w", encoding='utf-8') as f:
        f.write("This is a safe document.")
    print("Test environment created.")

    # --- Test Cases ---
    test_filenames = [
        "document1.txt",                          # 1. Valid file
        "nonexistent.txt",                        # 2. File not found
        "../main.py",                             # 3. Simple traversal attempt
        "document1.txt/../../main.py",            # 4. Nested traversal attempt
        "/etc/passwd"                             # 5. Absolute path attempt
    ]

    print("\n--- Running Test Cases ---")
    for i, filename in enumerate(test_filenames, 1):
        print(f"Test Case {i}: Requesting \"{filename}\"")
        result = read_file_from_safe_directory(filename)
        print(f"Result: {result}")
        print("--------------------")

    # --- Test Environment Teardown ---
    shutil.rmtree(SAFE_DIRECTORY)
    print("\nTest environment cleaned up.")


if __name__ == "__main__":
    main()