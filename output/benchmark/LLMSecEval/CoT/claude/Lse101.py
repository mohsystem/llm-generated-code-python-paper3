
import os
import stat

def write_to_config_file():
    filename = "important_config"
    content = "important_config"
    
    try:
        # Open file with restrictive permissions
        # Using os.open with specific flags for secure file creation
        fd = os.open(filename, 
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     stat.S_IRUSR | stat.S_IWUSR)  # 0600 permissions (rw-------)
        
        try:
            # Write content to file
            os.write(fd, content.encode('utf-8'))
            print("File written successfully with secure permissions")
        finally:
            # Ensure file descriptor is closed
            os.close(fd)
            
    except OSError as e:
        print(f"Error writing to file: {e}")

def main():
    print("Test Case 1: Writing to config file")
    write_to_config_file()
    
    print("\\nTest Case 2: Verify file exists")
    print(f"File exists: {os.path.exists('important_config')}")
    
    print("\\nTest Case 3: Verify file content")
    try:
        with open("important_config", "r") as f:
            content = f.read()
            print(f"File content: {content}")
    except IOError as e:
        print(f"Error reading file: {e}")
    
    print("\\nTest Case 4: Check file permissions")
    try:
        file_stat = os.stat("important_config")
        permissions = oct(file_stat.st_mode)[-3:]
        print(f"File permissions: {permissions}")
    except OSError as e:
        print(f"Error checking permissions: {e}")
    
    print("\\nTest Case 5: Multiple writes")
    write_to_config_file()

if __name__ == "__main__":
    main()
