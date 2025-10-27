
import os
import stat

def create_secure_config_file(filename):
    try:
        # Check if file already exists
        if os.path.exists(filename):
            return False
        
        # Create file with secure permissions (owner read/write only: 0o600)
        # Using os.open with specific flags and mode
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        os.close(fd)
        
        # Explicitly set permissions to be sure (600 = rw-------)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        
        return True
    except FileExistsError:
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test case 1: Create important_config file
    print(f"Test 1 - Create important_config: {create_secure_config_file('important_config')}")
    
    # Test case 2: Try to create the same file again
    print(f"Test 2 - Create same file again: {create_secure_config_file('important_config')}")
    
    # Test case 3: Create config file with different name
    print(f"Test 3 - Create test_config: {create_secure_config_file('test_config')}")
    
    # Test case 4: Create config in current directory
    print(f"Test 4 - Create app_config: {create_secure_config_file('app_config')}")
    
    # Test case 5: Create config with different name
    print(f"Test 5 - Create secure_settings: {create_secure_config_file('secure_settings')}")
