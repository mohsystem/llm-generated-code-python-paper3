import os
import sys

def create_secure_file(filename: str) -> bool:
    """
    Creates a file with secure permissions (0o600: owner read/write only).
    The operation is atomic, preventing race conditions. It will fail if the
    file already exists.

    Args:
        filename: The name of the file to create.

    Returns:
        True if the file was created successfully, False otherwise.
    """
    fd = -1
    try:
        # O_CREAT: Create the file if it does not exist.
        # O_EXCL: If O_CREAT is also specified, this ensures that this call creates the file.
        #         If the path already exists, open() will fail. This is atomic.
        # O_WRONLY: Open for writing only.
        # O_NOFOLLOW: Do not follow symbolic links.
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW

        # mode 0o600: Read and write permissions for the owner only.
        mode = 0o600
        
        fd = os.open(filename, flags, mode)
        print(f"Successfully created file: {filename}")
        return True
    except FileExistsError:
        print(f"Error creating file: {filename} already exists.", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error creating file {filename}: {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)

def main():
    """Main function with test cases."""
    test_files = [
        "important_config_1.txt",
        "important_config_2.cfg",
        "another_secure_file.dat",
        "test_config.ini",
        "user_settings.json"
    ]
    
    print("--- Running 5 Test Cases ---")

    for i, filename in enumerate(test_files):
        print(f"\n--- Test Case {i + 1}: {filename} ---")
        
        # 1. Attempt to create the file (should succeed)
        print("Attempt 1: Creating file.")
        create_secure_file(filename)

        # 2. Attempt to create the same file again (should fail)
        print("Attempt 2: Creating the same file again.")
        create_secure_file(filename)

        # 3. Clean up the created file
        try:
            os.remove(filename)
            print(f"Cleaned up file: {filename}")
        except OSError as e:
            print(f"Failed to clean up file {filename}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()