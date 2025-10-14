
import tempfile
import secrets
import string
import os

CHARACTERS = string.ascii_letters + string.digits
RANDOM_STRING_LENGTH = 20

def create_temp_file_with_random_string():
    # Generate secure random string
    random_string = ''.join(secrets.choice(CHARACTERS) for _ in range(RANDOM_STRING_LENGTH))
    
    # Create temporary file with UTF-8 encoding and restrictive permissions
    # mode 0o600 = read/write for owner only
    fd = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt', prefix='secure_temp_')
    
    try:
        # Set restrictive file permissions
        os.chmod(fd.name, 0o600)
        
        # Write Unicode string to file
        fd.write(random_string)
        fd.flush()
        
        temp_file_path = fd.name
    finally:
        fd.close()
    
    # Return absolute path
    return os.path.abspath(temp_file_path)

def main():
    print("Testing temporary file creation with random Unicode strings:\\n")
    
    for i in range(1, 6):
        try:
            file_path = create_temp_file_with_random_string()
            print(f"Test {i}: {file_path}")
            
            # Verify file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"  Content: {content}")
            print(f"  Length: {len(content)} characters\\n")
        except Exception as e:
            print(f"Test {i} failed: {e}")

if __name__ == "__main__":
    main()
