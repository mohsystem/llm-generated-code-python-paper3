import os
import sys

def write_config(filename, content):
    """
    Opens a file using flags equivalent to O_RDWR | O_CREAT and writes content.
    Sets secure file permissions (0600) upon creation.
    
    Args:
        filename (str): The name of the file to open/create.
        content (str): The string content to write to the file.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        # O_RDWR: Open for reading and writing.
        # O_CREAT: Create the file if it does not exist.
        flags = os.O_RDWR | os.O_CREAT
        
        # S_IRUSR | S_IWUSR: File mode 0600 (owner can read/write).
        # This is a security best practice for new files.
        # In Python, octal literals are prefixed with 0o.
        mode = 0o600
        
        # os.open() returns a low-level file descriptor.
        # We must ensure it's closed, so we use a try/finally block.
        fd = -1
        try:
            fd = os.open(filename, flags, mode)
            # Truncate file to 0 bytes before writing
            os.ftruncate(fd, 0)
            # Encode content to bytes for writing
            byte_content = content.encode('utf-8')
            bytes_written = os.write(fd, byte_content)
            # Ensure all content was written
            return bytes_written == len(byte_content)
        finally:
            if fd != -1:
                os.close(fd)
                
    except (IOError, OSError) as e:
        # Use sys.stderr for error messages
        print(f"Error writing to file '{filename}': {e}", file=sys.stderr)
        return False

def main():
    content = "important_config"
    test_files = [
        "config1.txt",
        "test/config2.txt", # Note: This will fail if 'test' directory doesn't exist.
        "config3.txt",
        "config4.txt",
        "config5.txt"
    ]

    # Create a directory for the second test case
    if not os.path.exists("test"):
        os.makedirs("test")

    for filename in test_files:
        print(f"Attempting to write to: {filename}")
        result = write_config(filename, content)
        print(f"  -> Success: {result}")
        if result and os.path.exists(filename):
            os.remove(filename) # Clean up created file

    # Clean up the created directory
    if os.path.exists("test"):
        os.rmdir("test")

if __name__ == "__main__":
    main()