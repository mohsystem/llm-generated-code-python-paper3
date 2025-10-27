import os
import stat
import sys

def create_and_write_file(filename, content):
    """
    Creates a file if it doesn't exist with specific permissions (0644),
    opens it for reading/writing, and writes content to it.
    This function is designed to be secure against TOCTOU vulnerabilities
    by using O_NOFOLLOW and fstat.

    Args:
        filename (str): The name of the file to open/create.
        content (str): The string content to write to the file.

    Returns:
        bool: True on success, False on failure.
    """
    fd = -1
    try:
        # Define flags: Read/Write, Create if not exists, and do not follow symlinks.
        # O_NOFOLLOW is a crucial security feature to prevent symlink attacks.
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW

        # Define permissions: S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH (0644)
        # Owner: read/write, Group: read, Others: read
        mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

        # Open the file, getting a file descriptor.
        fd = os.open(filename, flags, mode)

        # Security check: After opening, validate the file handle.
        # This prevents race conditions where the file could be replaced
        # by a symlink or directory between check and use.
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            print(f"Error: '{filename}' is not a regular file.", file=sys.stderr)
            return False

        # Write the content. First, encode the string to bytes.
        content_bytes = content.encode('utf-8')
        
        # Truncate the file to 0 bytes before writing to ensure it only contains new content.
        os.ftruncate(fd, 0)
        bytes_written = os.write(fd, content_bytes)

        if bytes_written != len(content_bytes):
            print(f"Error: Partial write to '{filename}'.", file=sys.stderr)
            return False
        
        return True

    except OSError as e:
        print(f"Error processing file '{filename}': {e}", file=sys.stderr)
        return False
    finally:
        # Ensure the file descriptor is always closed.
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor for '{filename}': {e}", file=sys.stderr)


if __name__ == "__main__":
    # Test Case 1: The primary specified case
    print("Test Case 1: important_config")
    if create_and_write_file("important_config", "important_config"):
        print("  Success.")
    else:
        print("  Failure.")

    # Test Case 2: A different filename and content
    print("\nTest Case 2: another_config.txt")
    if create_and_write_file("another_config.txt", "some other data"):
        print("  Success.")
    else:
        print("  Failure.")

    # Test Case 3: Empty content
    print("\nTest Case 3: empty_file.cfg")
    if create_and_write_file("empty_file.cfg", ""):
        print("  Success.")
    else:
        print("  Failure.")

    # Test Case 4: File with special characters in name
    print("\nTest Case 4: file-with-hyphen.log")
    if create_and_write_file("file-with-hyphen.log", "log entry 1"):
        print("  Success.")
    else:
        print("  Failure.")
        
    # Test Case 5: Overwriting an existing file
    print("\nTest Case 5: Overwriting important_config")
    if create_and_write_file("important_config", "new content"):
        print("  Success.")
    else:
        print("  Failure.")