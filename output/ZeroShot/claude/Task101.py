
import os
import stat

def create_executable_script(filename):
    try:
        # Create the file
        with open(filename, 'w') as f:
            f.write("#!/bin/bash\\n")
        
        # Make it executable
        st = os.stat(filename)
        os.chmod(filename, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        
        return True
    except Exception as e:
        print(f"Error creating file: {e}")
        return False

if __name__ == "__main__":
    # Test case 1: Create script.sh
    print("Test 1: Creating script.sh")
    result1 = create_executable_script("script.sh")
    print(f"Result: {'Success' if result1 else 'Failed'}")
    
    # Test case 2: Create test1.sh
    print("\\nTest 2: Creating test1.sh")
    result2 = create_executable_script("test1.sh")
    print(f"Result: {'Success' if result2 else 'Failed'}")
    
    # Test case 3: Create test2.sh
    print("\\nTest 3: Creating test2.sh")
    result3 = create_executable_script("test2.sh")
    print(f"Result: {'Success' if result3 else 'Failed'}")
    
    # Test case 4: Overwrite existing file
    print("\\nTest 4: Creating script.sh again (overwrites)")
    result4 = create_executable_script("script.sh")
    print(f"Result: {'Success' if result4 else 'Failed'}")
    
    # Test case 5: Create another script
    print("\\nTest 5: Creating deploy.sh")
    result5 = create_executable_script("deploy.sh")
    print(f"Result: {'Success' if result5 else 'Failed'}")
    
    # Cleanup test files
    for filename in ["script.sh", "test1.sh", "test2.sh", "deploy.sh"]:
        if os.path.exists(filename):
            os.remove(filename)
