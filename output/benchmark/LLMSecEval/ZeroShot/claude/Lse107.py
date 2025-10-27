
import os
import stat

def create_and_secure_file(filename, content):
    try:
        # Create file and write content
        with open(filename, 'w') as f:
            f.write(content)
        
        # Change permissions to restrictive (owner read/write only - 0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
        # Print permissions
        file_stats = os.stat(filename)
        permissions = oct(file_stats.st_mode)[-3:]
        print(f"Permissions for {filename}: {permissions}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test case 1: Create secret.txt with encrypted content
    print("Test Case 1:")
    create_and_secure_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    print()
    
    # Test case 2: Create another secure file
    print("Test Case 2:")
    create_and_secure_file("test1.txt", "Confidential Data")
    print()
    
    # Test case 3: Create file with different content
    print("Test Case 3:")
    create_and_secure_file("test2.txt", "Sensitive Information")
    print()
    
    # Test case 4: Create file with empty content
    print("Test Case 4:")
    create_and_secure_file("test3.txt", "")
    print()
    
    # Test case 5: Create file with special characters
    print("Test Case 5:")
    create_and_secure_file("test4.txt", "Special@#$%^&*()")
    print()
