import os
import sys

def create_secret_file(filename: str, content: str) -> bool:
    """
    Creates a file with restrictive permissions and writes content to it.

    This function atomically creates a file, writes content, and sets
    permissions to read/write for the owner only (0o600). It will fail
    if the file already exists to prevent overwriting.

    Args:
        filename (str): The name of the file to create.
        content (str): The content to write to the file.

    Returns:
        bool: True on success, False on failure.
    """
    try:
        # Encode content to bytes for writing
        content_bytes = content.encode('utf-8')

        # Flags for atomic, exclusive creation with write-only access.
        # os.O_CREAT: Create file if it does not exist.
        # os.O_EXCL: Error if file exists.
        # os.O_WRONLY: Open for writing only.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        
        # Permissions: 0o600 (read/write for owner only)
        mode = 0o600

        # os.open() is the low-level, secure way to do this.
        # It's an atomic operation on POSIX-compliant systems.
        fd = -1
        try:
            fd = os.open(filename, flags, mode)
            bytes_written = os.write(fd, content_bytes)
            if bytes_written != len(content_bytes):
                # This is unlikely but should be handled.
                sys.stderr.write(f"Error: Incomplete write to file: {filename}\n")
                # Attempt to clean up the partially written file
                os.close(fd)
                os.unlink(filename)
                return False
        finally:
            # Ensure the file descriptor is always closed if it was opened.
            if fd != -1:
                os.close(fd)
        
        print(f"Successfully created and secured file: {filename}")
        return True

    except FileExistsError:
        sys.stderr.write(f"Error: File already exists: {filename}\n")
        return False
    except OSError as e:
        sys.stderr.write(f"An OS error occurred for {filename}: {e}\n")
        return False
    except Exception as e:
        sys.stderr.write(f"An unexpected error occurred for {filename}: {e}\n")
        return False

def main():
    """Main function to run test cases."""
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    print("--- Running Test Cases ---")
    
    test_files = [f"secret{i}.txt" for i in range(1, 6)]

    # Test Cases 1-5: Create files
    for filename in test_files:
        print(f"\n--- Test: Create {filename} ---")
        create_secret_file(filename, content)

    # Additional Test: Try creating an existing file to test failure
    print(f"\n--- Test: Attempt to re-create {test_files[1]} (should fail) ---")
    create_secret_file(test_files[1], content)

    print("\n--- Cleaning up created files ---")
    for filename in test_files:
        try:
            if os.path.exists(filename):
                os.remove(filename)
        except OSError as e:
            sys.stderr.write(f"Failed to clean up {filename}: {e}\n")
    print("Cleanup complete.")


if __name__ == "__main__":
    main()