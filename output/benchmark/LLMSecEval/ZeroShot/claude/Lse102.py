
import os
import stat

def write_important_config(filename, content):
    try:
        # Open file with O_CREAT flag (create if doesn't exist)
        # Set permissions: owner read/write, group read, others read (0o644)
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        
        # Write content to file
        os.write(fd, content.encode())
        
        # Close file descriptor
        os.close(fd)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test case 1
    write_important_config("important_config", "important_config")
    
    # Test case 2
    write_important_config("test_config1.txt", "Configuration data 1")
    
    # Test case 3
    write_important_config("test_config2.txt", "Configuration data 2")
    
    # Test case 4
    write_important_config("test_config3.txt", "Secure configuration settings")
    
    # Test case 5
    write_important_config("test_config4.txt", "Application configuration")
