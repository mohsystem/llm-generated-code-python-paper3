
import os
import stat

def create_secret_file(filename, content):
    try:
        # Write content to file
        with open(filename, 'w') as f:
            f.write(content)
        
        # Set restrictive permissions (owner read/write only: 0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
        print(f"File '{filename}' created successfully with restrictive permissions.")
    except IOError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Permission error: {e}")

if __name__ == "__main__":
    # Test case 1: Standard execution
    create_secret_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 2: Different filename
    create_secret_file("secret2.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 3: Empty content
    create_secret_file("secret3.txt", "")
    
    # Test case 4: Longer content
    create_secret_file("secret4.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 5: Special characters in content
    create_secret_file("secret5.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==!@#$%")
