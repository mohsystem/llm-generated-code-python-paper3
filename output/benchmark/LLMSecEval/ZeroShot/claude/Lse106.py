
import os
import stat

def create_secret_file(secret_info, filename):
    try:
        # Write the secret info to file
        with open(filename, 'w') as f:
            f.write(secret_info)
        
        # Change permissions to read-only for owner (0o400)
        os.chmod(filename, stat.S_IRUSR)
        
        return filename
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test case 1
    filename1 = "secret1.txt"
    result1 = create_secret_file("Super secret password: admin123", filename1)
    print(result1)
    
    # Test case 2
    filename2 = "secret2.txt"
    result2 = create_secret_file("API Key: abc123xyz789", filename2)
    print(result2)
    
    # Test case 3
    filename3 = "secret3.txt"
    result3 = create_secret_file("Database credentials: user=root, pass=secret", filename3)
    print(result3)
    
    # Test case 4
    filename4 = "secret4.txt"
    result4 = create_secret_file("Private key: RSA-2048-BEGIN", filename4)
    print(result4)
    
    # Test case 5
    filename5 = "secret5.txt"
    result5 = create_secret_file("Social Security Number: 123-45-6789", filename5)
    print(result5)
