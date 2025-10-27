import os
import stat
import sys

def create_and_write_config(filename, content):
    """
    Opens/creates a file with specific permissions and writes content to it.
    The file is opened for reading and writing, created if it doesn't exist,
    and truncated if it does.

    Args:
        filename (str): The name of the file.
        content (str): The content to write.

    Returns:
        bool: True on success, False on failure.
    """
    fd = -1  # Initialize file descriptor to an invalid value
    try:
        # Define flags for opening the file: Read/Write, Create if not exists, Truncate if exists.
        flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        
        # Define permissions: Owner can read/write, Group and Others can read. (0644)
        mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        
        # Open the file, getting a file descriptor. This is an atomic operation.
        fd = os.open(filename, flags, mode)
        
        # Convert content string to bytes for writing
        content_bytes = content.encode('utf-8')
        
        # Write the content
        bytes_written = os.write(fd, content_bytes)
        
        if bytes_written != len(content_bytes):
            sys.stderr.write(f"Error: Incomplete write to '{filename}'\n")
            return False
            
        return True

    except OSError as e:
        sys.stderr.write(f"Error operating on file '{filename}': {e}\n")
        return False
        
    finally:
        # Ensure the file descriptor is closed even if an error occurs
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                # Log error but don't re-raise, as the primary error is more important
                sys.stderr.write(f"Error closing file descriptor for '{filename}': {e}\n")

def main():
    """ Main function to run test cases. """
    filename = "important_config"
    content = "important_config"
    
    print("Running 5 test cases...")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        print(f"Attempting to write '{content}' to '{filename}'")
        success = create_and_write_config(filename, content)
        if success:
            print("Successfully wrote to file.")
            # Optional verification
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    read_content = f.read()
                    print(f'File content verified: "{read_content}"')
            except IOError as e:
                sys.stderr.write(f"Failed to read back for verification: {e}\n")
        else:
            sys.stderr.write("Failed to write to file.\n")

if __name__ == "__main__":
    main()