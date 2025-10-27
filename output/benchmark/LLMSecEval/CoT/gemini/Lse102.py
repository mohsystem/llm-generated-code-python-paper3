import os
import stat

def create_and_write_file(filename, content):
    """
    Opens/creates a file for reading and writing with specific permissions 
    and writes content to it.

    Args:
        filename (str): The path to the file.
        content (str): The string content to write.

    Returns:
        bool: True if successful, False otherwise.
    """
    # Flags: Open for Read/Write, Create if not exists, Truncate if exists.
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    
    # Permissions: rw-r--r-- (0644 in octal)
    # This corresponds to S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

    fd = -1
    try:
        # os.open() is a low-level call that allows setting mode on creation
        fd = os.open(filename, flags, mode)
        
        content_bytes = content.encode('utf-8')
        bytes_written = os.write(fd, content_bytes)

        if bytes_written != len(content_bytes):
            print(f"Error: Partial write to file '{filename}'")
            return False
            
        return True
    except OSError as e:
        print(f"Error processing file '{filename}': {e}")
        return False
    finally:
        if fd != -1:
            os.close(fd)

def main():
    """Main function with test cases."""
    test_cases = [
        ("important_config", "important_config"),
        ("test_python_1.cfg", "some_data_1"),
        ("test_python_2.cfg", "some_data_2"),
        ("test_python_3.cfg", "some_data_3"),
        ("test_python_4.cfg", "some_data_4"),
    ]

    for filename, content in test_cases:
        print(f"--- Python Test Case: {filename} ---")
        success = create_and_write_file(filename, content)
        print(f"Operation successful: {success}")
        
        if success:
            try:
                # Clean up the created file
                os.remove(filename)
                print(f"Cleaned up file: {filename}")
            except OSError as e:
                print(f"Failed to clean up file '{filename}': {e}")
        print()

if __name__ == "__main__":
    main()