
import os
import stat

def write_config_to_file(filename, content):
    """\n    Securely write content to a file with restricted permissions.\n    \n    Args:\n        filename: Name of the file to write to\n        content: String content to write\n    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    if content is None:
        content = ""
    
    # Normalize path to prevent directory traversal
    filename = os.path.normpath(filename)
    
    try:
        # Open file with flags: O_RDWR (read/write), O_CREAT (create if not exists)
        # Set permissions to 0o600 (owner read/write only)
        fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        
        try:
            # Write content to file
            content_bytes = content.encode('utf-8')
            os.write(fd, content_bytes)
            print(f"Successfully wrote to file: {filename}")
        finally:
            # Always close the file descriptor
            os.close(fd)
            
    except OSError as e:
        print(f"Error writing to file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    print("Test Case 1: Normal write")
    write_config_to_file("config1.txt", "important_config")
    
    print("\\nTest Case 2: Empty content")
    write_config_to_file("config2.txt", "")
    
    print("\\nTest Case 3: Long content")
    write_config_to_file("config3.txt", "important_config_with_more_data_12345")
    
    print("\\nTest Case 4: Special characters")
    write_config_to_file("config4.txt", "important_config\\nline2\\ttab")
    
    print("\\nTest Case 5: Overwrite existing")
    write_config_to_file("config1.txt", "important_config_updated")
