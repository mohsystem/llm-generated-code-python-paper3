import os
import sys

def create_and_write_file(filename, content):
    """
    Opens/creates a file with specific permissions using low-level I/O
    and writes content to it.
    
    Args:
        filename (str): The name of the file.
        content (str): The content to write.
    """
    # Flags: O_RDWR for read/write, O_CREAT to create if it doesn't exist.
    flags = os.O_RDWR | os.O_CREAT
    
    # Permissions: rw-r--r-- (owner: read/write, group: read, others: read)
    # This corresponds to S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH or 0o644.
    # Note: The mode is only effective on POSIX systems.
    mode = 0o644
    
    fd = -1  # Initialize file descriptor
    try:
        # Open the file, getting a low-level file descriptor
        fd = os.open(filename, flags, mode)
        
        # Convert content to bytes for writing
        byte_content = content.encode('utf-8')
        
        # Move to the beginning of the file to overwrite content if file exists
        os.lseek(fd, 0, os.SEEK_SET)
        
        # Write the bytes to the file
        bytes_written = os.write(fd, byte_content)
        
        # Truncate the file to the new length in case the new content is shorter
        os.ftruncate(fd, bytes_written)
        
        print(f"Successfully wrote {bytes_written} bytes to {filename}.")
    except OSError as e:
        print(f"Error processing file {filename}: {e}", file=sys.stderr)
    finally:
        # Ensure the file descriptor is closed if it was opened
        if fd != -1:
            os.close(fd)

if __name__ == "__main__":
    print("--- Python Test Cases ---")
    # Test Case 1: As per the prompt
    create_and_write_file("important_config", "important_config")
    # Test Case 2: A different file and content
    create_and_write_file("python_test.log", "Log entry from Python.")
    # Test Case 3: A file with empty content
    create_and_write_file("python_empty.txt", "")
    # Test Case 4: Overwriting the first file
    create_and_write_file("important_config", "new important_config content from Python")
    # Test Case 5: Another new file
    create_and_write_file("python_data.json", "{\"key\": \"value\"}")
    print("-------------------------\n")