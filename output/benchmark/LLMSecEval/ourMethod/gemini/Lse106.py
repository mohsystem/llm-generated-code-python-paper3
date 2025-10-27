import os
import stat
import tempfile
import sys
from typing import Optional, List

def create_secret_file(secret_info: str) -> Optional[str]:
    """
    Creates a temporary file, writes secret info to it, and sets permissions
    to read-only for the owner (0400).
    
    Returns the file path on success, None on failure.
    """
    fd = -1
    path = ""
    try:
        # 1. Create a temporary file securely. mkstemp is the preferred way,
        # creating the file with secure permissions (typically 0600) to avoid race conditions.
        fd, path = tempfile.mkstemp(prefix="secret_", suffix=".txt")

        # 2. Write the secret info to it using the file descriptor.
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(secret_info)
        # The 'with' block automatically closes the file descriptor fd.
        fd = -1 

        # 3. Change permissions to read-only for the owner (0400).
        os.chmod(path, stat.S_IRUSR)

        # 4. Return the name of the file.
        return path
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        # Cleanup if something went wrong during the process.
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        return None

def main():
    """ Main function with 5 test cases and cleanup. """
    print("Running Python test cases...")
    created_files: List[str] = []
    for i in range(5):
        print(f"\n--- Test Case {i + 1} ---")
        secret = f"Python super secret info #{i + 1}"
        file_name = create_secret_file(secret)
        
        if file_name:
            print(f"Secret file created: {file_name}")
            created_files.append(file_name)
            # Verify permissions for demonstration
            try:
                mode = os.stat(file_name).st_mode
                print(f"File permissions: {stat.filemode(mode)}")
            except OSError as e:
                 print(f"Could not stat file: {e}", file=sys.stderr)
        else:
            print("Failed to create secret file.", file=sys.stderr)

    # Cleanup created files
    print("\nCleaning up created files...")
    for f in created_files:
        try:
            os.remove(f)
            print(f"Removed: {f}")
        except OSError as e:
            print(f"Error removing file {f}: {e}", file=sys.stderr)
    print("\nPython tests finished.")


if __name__ == "__main__":
    main()