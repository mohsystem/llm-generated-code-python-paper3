
import os
import stat

def create_important_config():
    try:
        # Create file with mode 0o600 (rw-------)
        fd = os.open("important_config", os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test case 1
    print("Test 1: Creating important_config file")
    print(f"Result: {create_important_config()}")
    
    # Test case 2
    print("\\nTest 2: Checking if file exists")
    print(f"File exists: {os.path.exists('important_config')}")
    
    # Test case 3
    print("\\nTest 3: Checking file permissions")
    if os.path.exists('important_config'):
        file_stat = os.stat('important_config')
        mode = oct(file_stat.st_mode)[-3:]
        print(f"File permissions: {mode}")
        print(f"Can read: {os.access('important_config', os.R_OK)}")
        print(f"Can write: {os.access('important_config', os.W_OK)}")
    
    # Test case 4
    print("\\nTest 4: Attempting to create file again")
    print(f"Result: {create_important_config()}")
    
    # Test case 5 - Cleanup
    print("\\nTest 5: Cleanup - deleting file")
    if os.path.exists('important_config'):
        os.remove('important_config')
        print("Deleted: True")
    else:
        print("Deleted: False")
