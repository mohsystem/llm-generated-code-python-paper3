
import os
import secrets
import stat
from pathlib import Path

def create_secret_file(secret_info):
    """\n    Create a file with secret info and set read-only permissions for owner.\n    Returns the filename.\n    """
    # Use secure random for unique filename to prevent prediction
    random_hex = secrets.token_hex(16)
    filename = f"secret_{random_hex}.txt"
    
    # Create file in secure temp directory
    temp_dir = Path("/tmp") if os.name != 'nt' else Path(os.environ.get('TEMP', '.'))
    filepath = temp_dir / filename
    
    # Convert secret to bytes
    secret_bytes = secret_info.encode('utf-8')
    
    try:
        # Open file with restrictive permissions from creation (0600)
        # O_CREAT | O_EXCL ensures atomic creation and fails if exists
        # O_WRONLY for write-only access during creation
        fd = os.open(
            filepath,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
            mode=0o600  # Owner read/write only during creation
        )
        
        try:
            # Write secret data
            os.write(fd, secret_bytes)
            # Ensure data is written to disk
            os.fsync(fd)
        finally:
            # Close file descriptor
            os.close(fd)
        
        # Change permissions to read-only for owner (0400)
        os.chmod(filepath, stat.S_IRUSR)
        
        # Clear sensitive data from memory (best effort in Python)
        secret_bytes = bytearray(len(secret_bytes))
        
        return str(filepath)
        
    except Exception as e:
        # Clear sensitive data on error
        secret_bytes = bytearray(len(secret_bytes))
        raise e

def main():
    # Test cases
    test_secrets = [
        "SuperSecret123!",
        "ClassifiedInformation",
        "TopSecretData",
        "ConfidentialInfo",
        "RestrictedAccess"
    ]
    
    for secret in test_secrets:
        try:
            filename = create_secret_file(secret)
            print(filename)
        except Exception as e:
            print(f"Error creating secret file: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
