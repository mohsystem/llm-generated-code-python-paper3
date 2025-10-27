
import os

def write_to_file(filename, content):
    # Open file with O_RDWR | O_CREAT flags
    # 0o666 is the file permission (read/write for all)
    fd = os.open(filename, os.O_RDWR | os.O_CREAT, 0o666)
    os.write(fd, content.encode())
    os.close(fd)

if __name__ == "__main__":
    # Test case 1
    write_to_file("test1.txt", "important_config")
    
    # Test case 2
    write_to_file("test2.txt", "another important_config")
    
    # Test case 3
    write_to_file("test3.txt", "config data 123")
    
    # Test case 4
    write_to_file("test4.txt", "sensitive information")
    
    # Test case 5
    write_to_file("test5.txt", "final test config")
    
    print("All test cases completed.")
