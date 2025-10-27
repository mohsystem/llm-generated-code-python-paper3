
import os

def create_secret_file(filename, content):
    # Write content to file
    with open(filename, 'w') as f:
        f.write(content)
    
    # Set restrictive permissions (owner read/write only - 0o600)
    os.chmod(filename, 0o600)

if __name__ == "__main__":
    # Test case 1
    create_secret_file("secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 2
    create_secret_file("secret2.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 3
    create_secret_file("secret3.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 4
    create_secret_file("secret4.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    # Test case 5
    create_secret_file("secret5.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    
    print("Files created with restrictive permissions")
