import os
import stat
from typing import List

def create_and_make_executable(filename: str) -> bool:
    """
    Creates a file, writes a simple shell script, and makes it executable.
    Uses file descriptors for chmod to mitigate TOCTOU vulnerabilities.

    :param filename: The name of the file. Must not contain path separators.
    :return: True on success, False on failure.
    """
    if not filename or '/' in filename or '\\' in filename:
        print(f"Error: Invalid filename '{filename}'. It must not be empty or contain path separators.")
        return False

    content = f"#!/bin/sh\necho \"Hello from {filename}!\"\n"

    try:
        # Clean up file if it exists from a previous run
        if os.path.exists(filename):
            os.remove(filename)

        # Open the file in write mode. The 'with' statement ensures it's closed.
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
            # Ensure data is written to the file on disk
            f.flush()
            os.fsync(f.fileno())

            # Get current permissions and add the execute permission for the owner.
            current_mode = os.fstat(f.fileno()).st_mode
            os.fchmod(f.fileno(), current_mode | stat.S_IXUSR)

        return True
    except (IOError, OSError) as e:
        print(f"An error occurred: {e}")
        return False

def main():
    """Main function with test cases."""
    test_filenames: List[str] = [
        "script1.sh",
        ".hidden_script.sh",
        "no_extension",
        "",  # Invalid: empty
        "test/script.sh"  # Invalid: contains path separator
    ]

    for filename in test_filenames:
        print(f"Testing with filename: \"{filename}\"")
        success = create_and_make_executable(filename)
        print(f"Result: {'SUCCESS' if success else 'FAILURE'}")
        if success:
            print(f"File '{filename}' created and made executable.")
            # Clean up the created file
            try:
                os.remove(filename)
                print(f"Cleaned up '{filename}'.")
            except OSError as e:
                print(f"Failed to clean up file '{filename}': {e}")
        print("--------------------")

if __name__ == "__main__":
    main()