
import os
import stat

def write_important_config(filename, content):
    # O_CREAT: create if doesn't exist, O_RDWR: read and write
    # S_IRUSR | S_IWUSR: owner read/write, S_IRGRP: group read, S_IROTH: others read
    flags = os.O_CREAT | os.O_RDWR | os.O_TRUNC
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    
    fd = os.open(filename, flags, mode)
    os.write(fd, content.encode())
    os.close(fd)

if __name__ == "__main__":
    # Test case 1
    write_important_config("important_config", "important_config")
    
    # Test case 2
    write_important_config("test_config1.txt", "Configuration data 1")
    
    # Test case 3
    write_important_config("test_config2.txt", "Configuration data 2")
    
    # Test case 4
    write_important_config("test_config3.txt", "Configuration data 3")
    
    # Test case 5
    write_important_config("test_config4.txt", "Configuration data 4")
    
    print("Files created successfully")
