
import os
import stat

def create_secure_file(secret_info, filename):
    try:
        # Create file with restrictive permissions (owner read-only: 0o400)
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o400)
        
        # Write secret info
        os.write(fd, secret_info.encode('utf-8'))
        os.close(fd)
        
        # Ensure permissions are set to read-only for owner
        os.chmod(filename, stat.S_IRUSR)
        
        return filename
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test cases
    test_cases = [
        "SuperSecret123!",
        "Confidential Data",
        "API_KEY=abc123xyz",
        "Password: P@ssw0rd!",
        "Token: eyJhbGciOiJIUzI1NiJ9"
    ]
    
    for i, secret in enumerate(test_cases, 1):
        filename = f"secret_file_{i}.txt"
        result = create_secure_file(secret, filename)
        print(result)

if __name__ == "__main__":
    main()
