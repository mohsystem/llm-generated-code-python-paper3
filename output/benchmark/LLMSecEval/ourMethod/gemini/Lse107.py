import os
import stat
import sys

def create_and_secure_file(file_name, content):
    """
    Creates a file, writes content, sets restrictive permissions, and prints them.

    Args:
        file_name (str): The name of the file to create.
        content (str): The string content to write.

    Returns:
        bool: True on success, False on failure.
    """
    fd = -1
    try:
        # Restrictive permissions: read/write for owner only (0o600)
        permissions = stat.S_IRUSR | stat.S_IWUSR
        
        # Atomically create a new file with restrictive permissions.
        # O_EXCL ensures that we don't open an existing file (avoiding a race condition).
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        
        # os.open is a low-level function that provides the needed flags for security.
        fd = os.open(file_name, flags, permissions)
        
        # Write content to the file using the file descriptor
        os.write(fd, content.encode('utf-8'))
        print(f"Successfully created and wrote to {file_name}")

        # Get the permissions using fstat on the file descriptor to avoid a TOCTOU race on the path
        file_stat = os.fstat(fd)
        # stat.filemode provides a human-readable string like '-rw-------'
        mode_str = stat.filemode(file_stat.st_mode)
        print(f"File permissions for {file_name}: {mode_str} (octal: {oct(stat.S_IMODE(file_stat.st_mode)):>04})")
        
        return True
    except FileExistsError:
        print(f"Error: File already exists: {file_name}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"An OS error occurred: {e}", file=sys.stderr)
        return False
    finally:
        # Ensure the file descriptor is always closed
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor: {e}", file=sys.stderr)


def main():
    """ Main function to run test cases. """
    file_name = "secret.txt"
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        success = create_and_secure_file(file_name, content)
        if success:
            print(f"Test case {i} successful.")
        else:
            print(f"Test case {i} failed.", file=sys.stderr)
            
        # Cleanup for the next run
        if os.path.exists(file_name):
            try:
                os.remove(file_name)
            except OSError as e:
                print(f"Failed to clean up file {file_name}: {e}", file=sys.stderr)
        print()

if __name__ == "__main__":
    main()