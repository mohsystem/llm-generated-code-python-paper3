
import os

def write_to_file(filename, content):
    try:
        # Open file with O_RDWR (read/write) and O_CREAT (create if not exists)
        # os.O_RDWR | os.O_CREAT combines the flags
        # 0o644 sets file permissions (owner can read/write, others can read)
        fd = os.open(filename, os.O_RDWR | os.O_CREAT, 0o644)
        
        # Write the content to the file
        os.write(fd, content.encode())
        
        # Close the file descriptor
        os.close(fd)
        
        print(f"Successfully wrote to file: {filename}")
    except Exception as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    # Test case 1
    write_to_file("config1.txt", "important_config")
    
    # Test case 2
    write_to_file("config2.txt", "database_settings=localhost:5432")
    
    # Test case 3
    write_to_file("config3.txt", "api_key=secret123")
    
    # Test case 4
    write_to_file("config4.txt", "timeout=30")
    
    # Test case 5
    write_to_file("config5.txt", "debug_mode=true")
