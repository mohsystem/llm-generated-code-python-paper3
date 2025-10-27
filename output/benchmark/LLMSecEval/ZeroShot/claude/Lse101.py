
import os
import stat

def write_to_file(filename, content):
    # Open file with restricted permissions (owner read/write only - 0o600)
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, content.encode('utf-8'))
    finally:
        os.close(fd)

if __name__ == "__main__":
    # Test case 1: Write to important_config
    write_to_file("important_config", "important_config")
    
    # Test case 2: Write different content
    write_to_file("test_config_1", "test_content_1")
    
    # Test case 3: Write empty string
    write_to_file("test_config_2", "")
    
    # Test case 4: Write multi-line content
    write_to_file("test_config_3", "line1\\nline2\\nline3")
    
    # Test case 5: Write special characters
    write_to_file("test_config_4", "special!@#$%^&*()")
    
    print("Files written successfully")
