
import os
import stat

def write_important_config(content):
    filename = "important_config"
    
    try:
        # Open file with O_CREAT flag, create if doesn't exist
        # Permissions: owner read/write (0600 initially for security)
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 
                     stat.S_IRUSR | stat.S_IWUSR)
        
        try:
            # Write content to file
            os.write(fd, content.encode())
        finally:
            # Always close file descriptor
            os.close(fd)
        
        # Set final permissions: owner read/write, group read, others read (0644)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        
        return True
    except OSError as e:
        print(f"Error writing to file: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test 1:", write_important_config("important_config"))
    print("Test 2:", write_important_config("test_data_1"))
    print("Test 3:", write_important_config("configuration_value"))
    print("Test 4:", write_important_config("secure_settings"))
    print("Test 5:", write_important_config(""))
