
import os
import stat

def create_executable_script(filename):
    try:
        # Create the file
        with open(filename, 'w') as f:
            f.write("#!/bin/bash\\n")
            f.write("echo 'Hello from script.sh'\\n")
        
        # Make it executable
        st = os.stat(filename)
        os.chmod(filename, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test case 1: Create script.sh
    print("Test 1:", create_executable_script("script.sh"))
    
    # Test case 2: Create test1.sh
    print("Test 2:", create_executable_script("test1.sh"))
    
    # Test case 3: Create test2.sh
    print("Test 3:", create_executable_script("test2.sh"))
    
    # Test case 4: Create test3.sh
    print("Test 4:", create_executable_script("test3.sh"))
    
    # Test case 5: Create test4.sh
    print("Test 5:", create_executable_script("test4.sh"))
