
import os
import stat

def create_secret_file(filename, content):
    try:
        # Write content to file
        with open(filename, 'w') as f:
            f.write(content)
        
        # Set restrictive permissions (owner read/write only - 0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
    except Exception as e:
        print(f"Error: {e}")

def main():
    # Test case 1: Default secret.txt
    create_secret_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 2: Different filename
    create_secret_file("secret2.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 3: Different content
    create_secret_file("secret3.txt", "U2FsdGVkX1/TestData123==")
    
    # Test case 4: Another test file
    create_secret_file("secret4.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 5: Fifth test file
    create_secret_file("secret5.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("Secret files created with restrictive permissions")

if __name__ == "__main__":
    main()
