
import os
import stat

def create_restrictive_file(filename, content):
    """\n    Create a file with restrictive permissions (0600 - owner read/write only).\n    Opens file with os.open using O_CREAT|O_EXCL for atomic creation,\n    then sets restrictive permissions to prevent unauthorized access.\n    """
    # Define restrictive permissions: owner read/write only (0600)
    # This prevents any other user or group from accessing the file
    restrictive_perms = stat.S_IRUSR | stat.S_IWUSR  # 0600
    
    try:
        # Open file with O_CREAT|O_EXCL|O_WRONLY to atomically create and open
        # O_EXCL ensures we fail if file exists, preventing race conditions
        # Setting mode at creation time establishes restrictive permissions immediately
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, restrictive_perms)
        
        try:
            # Write content as bytes (UTF-8 encoded)
            os.write(fd, content.encode('utf-8'))
            
            # Explicitly set permissions again to ensure they are restrictive
            # This guards against umask interference
            os.fchmod(fd, restrictive_perms)
            
        finally:
            # Always close the file descriptor
            os.close(fd)
            
    except FileExistsError:
        # File already exists - remove it and try again for idempotent behavior
        os.remove(filename)
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, restrictive_perms)
        try:
            os.write(fd, content.encode('utf-8'))
            os.fchmod(fd, restrictive_perms)
        finally:
            os.close(fd)

if __name__ == "__main__":
    # Test cases
    test_files = [
        "secret.txt",
        "test1_secret.txt",
        "test2_secret.txt",
        "test3_secret.txt",
        "test4_secret.txt"
    ]
    
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    for test_file in test_files:
        try:
            create_restrictive_file(test_file, content)
            print(f"Successfully created {test_file} with restrictive permissions (0600)")
        except Exception as e:
            print(f"Failed to create {test_file}: {e}")
