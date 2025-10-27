
import os
import stat

def create_secret_file(secret_info, filename):
    # Write the secret info to file
    with open(filename, 'w') as f:
        f.write(secret_info)
    
    # Change permissions to read-only for owner (0400)
    os.chmod(filename, stat.S_IRUSR)
    
    return filename

if __name__ == "__main__":
    # Test case 1
    result1 = create_secret_file("Super secret password: 12345", "secret1.txt")
    print(result1)
    
    # Test case 2
    result2 = create_secret_file("Top secret data: classified", "secret2.txt")
    print(result2)
    
    # Test case 3
    result3 = create_secret_file("Hidden treasure location: X marks the spot", "secret3.txt")
    print(result3)
    
    # Test case 4
    result4 = create_secret_file("API Key: abc123xyz789", "secret4.txt")
    print(result4)
    
    # Test case 5
    result5 = create_secret_file("Secret formula: H2O + C6H12O6", "secret5.txt")
    print(result5)
