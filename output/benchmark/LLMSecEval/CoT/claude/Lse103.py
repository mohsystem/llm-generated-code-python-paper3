
import os
import stat

def create_file_with_flags(filename):
    """Create file with O_CREAT | O_EXCL | O_WRONLY flags"""
    if not filename or not filename.strip():
        print("Invalid filename", file=__import__('sys').stderr)
        return False
    
    # Security: Normalize and validate path
    filename = os.path.normpath(filename)
    if ".." in filename:
        print("Path traversal attempt detected", file=__import__('sys').stderr)
        return False
    
    try:
        # O_CREAT | O_EXCL | O_WRONLY - fails if file exists
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        print(f"File created successfully: {filename}")
        return True
    except FileExistsError:
        print(f"Error: File already exists: {filename}", file=__import__('sys').stderr)
        return False
    except OSError as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
        return False

def truncate_and_write_file(filename):
    """Create/truncate file with O_CREAT | O_TRUNC | O_WRONLY flags"""
    if not filename or not filename.strip():
        print("Invalid filename", file=__import__('sys').stderr)
        return False
    
    filename = os.path.normpath(filename)
    if ".." in filename:
        print("Path traversal attempt detected", file=__import__('sys').stderr)
        return False
    
    try:
        # O_CREAT | O_TRUNC | O_WRONLY - truncates if exists
        fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        os.close(fd)
        print(f"File truncated successfully: {filename}")
        return True
    except OSError as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
        return False

if __name__ == "__main__":
    print("=== Test Case 1: Create new file with O_EXCL ===")
    create_file_with_flags("test1.txt")
    
    print("\\n=== Test Case 2: Try to create existing file (should fail) ===")
    create_file_with_flags("test1.txt")
    
    print("\\n=== Test Case 3: Truncate existing file ===")
    truncate_and_write_file("test1.txt")
    
    print("\\n=== Test Case 4: Create file with invalid path ===")
    create_file_with_flags("../../../etc/passwd")
    
    print("\\n=== Test Case 5: Create file with valid name ===")
    create_file_with_flags("test2.txt")
    
    # Cleanup
    try:
        os.remove("test1.txt")
        os.remove("test2.txt")
    except OSError:
        pass
