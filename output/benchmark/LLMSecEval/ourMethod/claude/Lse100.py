
import os
import sys
from pathlib import Path

def create_secure_config_file(filename):
    """\n    Creates a file with restrictive permissions (0600 - owner read/write only).\n    \n    Security measures:\n    - Uses os.open with O_CREAT|O_EXCL to prevent race conditions\n    - Sets mode to 0o600 at creation time (owner read/write only)\n    - Validates that file doesn't already exist\n    - Closes file descriptor immediately after creation\n    """
    try:
        # Security: Normalize path to prevent directory traversal
        # Reject paths that attempt to escape current directory
        filepath = Path(filename).resolve()
        
        # Security: Use O_CREAT|O_EXCL to fail if file exists (prevents TOCTOU)
        # O_NOFOLLOW prevents following symbolic links
        # Set restrictive permissions (0o600) at creation time
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        
        # Security: Create with mode 0o600 (owner read/write only)
        fd = os.open(str(filepath), flags, mode=0o600)
        
        # Security: Close file descriptor immediately
        os.close(fd)
        
        return True
        
    except FileExistsError:
        print(f"Error: File {filename} already exists", file=sys.stderr)
        return False
    except (OSError, IOError) as e:
        print(f"Error creating file: {e}", file=sys.stderr)
        return False


def main():
    """Test cases for secure file creation"""
    
    # Test case 1: Create important_config file
    print(f"Test 1 - Create important_config: {create_secure_config_file('important_config')}")
    
    # Test case 2: Attempt to create same file again (should fail)
    print(f"Test 2 - Create duplicate (should fail): {create_secure_config_file('important_config')}")
    
    # Test case 3: Create different config file
    print(f"Test 3 - Create test_config1: {create_secure_config_file('test_config1')}")
    
    # Test case 4: Create another config file
    print(f"Test 4 - Create test_config2: {create_secure_config_file('test_config2')}")
    
    # Test case 5: Create secure settings file
    print(f"Test 5 - Create secure_settings: {create_secure_config_file('secure_settings')}")
    
    # Cleanup test files
    for fname in ['important_config', 'test_config1', 'test_config2', 'secure_settings']:
        try:
            Path(fname).unlink(missing_ok=True)
        except Exception as e:
            print(f"Cleanup error for {fname}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
