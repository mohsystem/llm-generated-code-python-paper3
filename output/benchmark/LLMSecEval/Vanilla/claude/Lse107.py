
import os
import stat

def create_and_secure_file(filename, content):
    try:
        # Create file and write content
        with open(filename, 'w') as f:
            f.write(content)
        
        # Change permissions to restrictive (owner read/write only: 0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
        # Print permissions
        file_stats = os.stat(filename)
        permissions = oct(file_stats.st_mode)[-3:]
        print(f"File permissions: {permissions}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    create_and_secure_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("\\nTest Case 2:")
    create_and_secure_file("secret2.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("\\nTest Case 3:")
    create_and_secure_file("secret3.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("\\nTest Case 4:")
    create_and_secure_file("secret4.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("\\nTest Case 5:")
    create_and_secure_file("secret5.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
