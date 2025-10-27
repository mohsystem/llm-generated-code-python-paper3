import os
import stat
import sys

def create_and_write_file(path, content):
    """
    Creates a file if it doesn't exist, opens it for reading/writing,
    and writes content to it using low-level I/O.
    This function adheres to secure practices by using a restrictive file mode,
    validating the file type after opening, and ensuring the file descriptor is closed.

    :param path: The path to the file.
    :param content: The string content to write to the file.
    :return: True if successful, False otherwise.
    """
    fd = -1
    try:
        # Open the file with flags: Read/Write, Create if not exists.
        # Set restrictive permissions (0o600) upon creation.
        # O_NOFOLLOW is not universally available, but is a good practice where it is.
        # It prevents opening a symlink.
        open_flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, 'O_NOFOLLOW'):
            open_flags |= os.O_NOFOLLOW

        fd = os.open(path, open_flags, stat.S_IRUSR | stat.S_IWUSR)

        # After opening, validate the handle.
        # fstat operates on the descriptor, avoiding a TOCTOU race condition.
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            print(f"Error: Path is not a regular file: {path}", file=sys.stderr)
            # The file was created, so we should clean it up.
            os.close(fd)
            os.remove(path)
            return False

        # Write the content to the file.
        content_bytes = content.encode('utf-8')
        bytes_written = os.write(fd, content_bytes)

        if bytes_written != len(content_bytes):
            print(f"Error: Incomplete write to file: {path}", file=sys.stderr)
            return False
            
        return True
    except OSError as e:
        print(f"An OS error occurred: {e}", file=sys.stderr)
        return False
    finally:
        # Ensure the file descriptor is closed.
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor: {e}", file=sys.stderr)

def main():
    """Main function with test cases."""
    important_config = "important_config=true"

    # Test cases
    test_files = [
        "test_config1.txt",
        "test_config2.txt",
        "test_config3.txt",
        "test_config4.txt",
        "test_config5.txt"
    ]

    for filename in test_files:
        print(f"Attempting to write to: {filename}")
        if create_and_write_file(filename, important_config):
            print(f"Successfully wrote to {filename}")
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    print(f"Content of {filename}: \"{content}\"")
                os.remove(filename)  # Clean up test file
                print(f"Cleaned up {filename}")
            except OSError as e:
                print(f"Failed to read or clean up {filename}: {e}", file=sys.stderr)
        else:
            print(f"Failed to write to {filename}", file=sys.stderr)
        print("--------------------")

if __name__ == "__main__":
    main()