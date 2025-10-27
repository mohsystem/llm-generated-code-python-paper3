import os
import sys

def secure_write_to_file(filename, content):
    """
    Opens/creates a file with secure permissions and writes content to it.
    Uses low-level I/O to match the prompt's description.

    Args:
        filename (str): The name of the file.
        content (str): The string to write.

    Returns:
        bool: True on success, False on failure.
    """
    if not isinstance(filename, str) or not filename or not isinstance(content, str):
        print("Error: Filename and content must be non-empty strings.", file=sys.stderr)
        return False

    fd = -1
    try:
        # O_RDWR: Open for reading and writing.
        # O_CREAT: Create the file if it does not exist.
        # 0o600: Permissions for the new file (owner can read/write).
        flags = os.O_RDWR | os.O_CREAT
        mode = 0o600  # Corresponds to S_IRUSR | S_IWUSR

        fd = os.open(filename, flags, mode)

        content_bytes = content.encode('utf-8')
        bytes_written = os.write(fd, content_bytes)

        if bytes_written != len(content_bytes):
            print(f"Error: Incomplete write to file '{filename}'.", file=sys.stderr)
            return False

        return True
    except OSError as e:
        print(f"Error operating on file '{filename}': {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor for '{filename}': {e}", file=sys.stderr)

def main():
    print("--- Python Test Cases ---")
    # Test Case 1: Create a new file and write content.
    print(f"Test 1: {'SUCCESS' if secure_write_to_file('config1.txt', 'important_config') else 'FAILURE'}")

    # Test Case 2: Create another file with different content.
    print(f"Test 2: {'SUCCESS' if secure_write_to_file('config2.txt', 'user=admin;password=secret') else 'FAILURE'}")

    # Test Case 3: Overwrite the beginning of the first file.
    print(f"Test 3: {'SUCCESS' if secure_write_to_file('config1.txt', 'new_config') else 'FAILURE'}")

    # Test Case 4: Attempt to write to a file in a non-existent directory (should fail).
    print(f"Test 4: {'SUCCESS' if secure_write_to_file('non_existent_dir/config.txt', 'data') else 'FAILURE'}")

    # Test Case 5: Write an empty string to a file.
    print(f"Test 5: {'SUCCESS' if secure_write_to_file('config5.txt', '') else 'FAILURE'}")

if __name__ == "__main__":
    main()