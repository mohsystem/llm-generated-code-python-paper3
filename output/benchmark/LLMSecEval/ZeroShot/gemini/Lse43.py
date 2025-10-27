import os
from pathlib import Path

# Define the absolute path to the safe directory
SAFE_DIRECTORY = Path("/safe/").resolve()

def read_file_from_safe_directory(filename: str) -> str:
    """
    Securely reads a file from the SAFE_DIRECTORY.
    It prevents path traversal attacks by resolving the canonical path and
    ensuring it is a child of the safe base directory.

    Args:
        filename: The name of the file to read.

    Returns:
        The content of the file as a string.

    Raises:
        ValueError: If a path traversal attempt is detected or the filename is invalid.
        FileNotFoundError: If the file does not exist.
        IOError: For other I/O related errors.
    """
    if not filename or ".." in filename.split(os.path.sep):
        raise ValueError(f"Invalid filename format or path traversal characters detected in '{filename}'")

    try:
        # Construct the full path and resolve it to its absolute, canonical form
        # This resolves symlinks and removes ".." parts.
        requested_path = SAFE_DIRECTORY.joinpath(filename).resolve()

        # Security Check: Verify that the resolved path is within the SAFE_DIRECTORY
        # by checking if SAFE_DIRECTORY is one of its parents.
        if SAFE_DIRECTORY not in requested_path.parents and requested_path != SAFE_DIRECTORY:
             raise ValueError(f"Path traversal attempt detected for file: {filename}")

        # Check if file exists and is a file (not a directory)
        if not requested_path.is_file():
            raise FileNotFoundError(f"File not found or is not a regular file: {requested_path}")

        with open(requested_path, 'r', encoding='utf-8') as f:
            return f.read()

    except FileNotFoundError:
        # Re-raising to be explicit
        raise FileNotFoundError(f"File not found: {filename}")
    except (IOError, OSError) as e:
        raise IOError(f"Error reading file {filename}: {e}") from e


def main():
    """Main function with test cases."""
    print("--- Running Python Test Cases ---")
    print("NOTE: For these tests to pass, create the /safe directory and files:")
    print("  sudo mkdir -p /safe/docs")
    print("  sudo chown -R $(whoami) /safe")
    print("  echo \"This is a safe report.\" > /safe/report.txt")
    print("  echo \"This is a nested manual.\" > /safe/docs/manual.pdf\n")

    test_filenames = [
        "report.txt",                 # 1. Valid file
        "docs/manual.pdf",            # 2. Valid file in a subdirectory
        "nonexistent.txt",            # 3. Non-existent file
        "../../../../etc/passwd",     # 4. Path traversal attempt
        "../safe/report.txt"          # 5. Another path traversal attempt
    ]

    for filename in test_filenames:
        print(f"--- Testing with filename: '{filename}' ---")
        try:
            content = read_file_from_safe_directory(filename)
            print("Successfully read file. Content:")
            print(content)
        except (ValueError, FileNotFoundError, IOError) as e:
            print(f"Caught expected exception: {type(e).__name__} - {e}")
        finally:
            print("----------------------------------------\n")

if __name__ == "__main__":
    main()