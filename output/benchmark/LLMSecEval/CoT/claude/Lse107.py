
import os
import stat

def create_secure_file(filename, content):
    try:
        # Create file and write content
        with open(filename, 'w') as f:
            f.write(content)
        
        # Set restrictive permissions (owner read/write only - 0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
        # Print permissions
        file_stats = os.stat(filename)
        permissions = oct(file_stats.st_mode)[-3:]
        print(f"File permissions: {permissions} ({filename})")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test case 1: Create secret.txt with encrypted data
    create_secure_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 2: Create another secure file
    create_secure_file("test1.txt", "SecureData123")
    
    # Test case 3: Create file with different content
    create_secure_file("test2.txt", "ConfidentialInfo")
    
    # Test case 4: Create file with empty content
    create_secure_file("test3.txt", "")
    
    # Test case 5: Create file with multi-line content
    create_secure_file("test4.txt", "Line1\\nLine2\\nLine3")
