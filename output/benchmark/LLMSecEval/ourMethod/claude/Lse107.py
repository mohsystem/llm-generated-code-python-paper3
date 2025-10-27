
import os
import stat
import sys

def create_and_secure_file(filename, content):
    """\n    Create a file with restrictive permissions and write content to it.\n    Uses os.open with O_CREAT|O_EXCL|O_WRONLY for secure creation.\n    """
    try:
        # Create file with restrictive permissions (0o600 - owner read/write only)
        # O_CREAT|O_EXCL ensures atomic creation and fails if file exists
        # O_WRONLY for write-only access, O_CLOEXEC to prevent descriptor leaks
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        mode = 0o600  # Owner read/write only, no permissions for group/others
        
        # Open file descriptor with secure flags and restrictive permissions
        fd = os.open(filename, flags, mode)
        
        try:
            # Write content using the file descriptor
            # Encode to UTF-8 for consistent handling
            content_bytes = content.encode('utf-8')
            os.write(fd, content_bytes)
            
            # Ensure data is written to disk
            os.fsync(fd)
            
        finally:
            # Always close the file descriptor
            os.close(fd)
        
        # Verify and print permissions using fstat on the opened descriptor
        # Open again for verification (read-only, no follow symlinks where supported)
        verify_fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC)
        try:
            file_stat = os.fstat(verify_fd)
            perms = stat.filemode(file_stat.st_mode)
            print(f"File permissions: {perms}")
            
            # Also print octal representation for clarity
            octal_perms = oct(file_stat.st_mode & 0o777)
            print(f"Octal permissions: {octal_perms}")
            
        finally:
            os.close(verify_fd)
            
    except FileExistsError:
        # File already exists, fail securely
        print(f"Error: File {filename} already exists", file=sys.stderr)
    except OSError as e:
        # Generic error handling without exposing internals
        print(f"Error creating or securing file", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)

def main():
    # Test case 1: Standard operation
    print("Test 1: Creating secret.txt")
    try:
        os.remove("secret.txt")
    except FileNotFoundError:
        pass
    create_and_secure_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 2: Different filename
    print("\\nTest 2: Creating secret2.txt")
    try:
        os.remove("secret2.txt")
    except FileNotFoundError:
        pass
    create_and_secure_file("secret2.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 3: Different content
    print("\\nTest 3: Creating secret3.txt with different content")
    try:
        os.remove("secret3.txt")
    except FileNotFoundError:
        pass
    create_and_secure_file("secret3.txt", "TestContent123")
    
    # Test case 4: Empty content
    print("\\nTest 4: Creating secret4.txt with empty content")
    try:
        os.remove("secret4.txt")
    except FileNotFoundError:
        pass
    create_and_secure_file("secret4.txt", "")
    
    # Test case 5: Special characters
    print("\\nTest 5: Creating secret5.txt with special characters")
    try:
        os.remove("secret5.txt")
    except FileNotFoundError:
        pass
    create_and_secure_file("secret5.txt", "Special!@#$%^&*()")

if __name__ == "__main__":
    main()
