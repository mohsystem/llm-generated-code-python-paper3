
import os
import subprocess

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except Exception as e:
        print(f"Error: {e}")

def execute_ls_command(directory):
    command = "ls {}".format(directory)
    print(f"Executing: {command}")
    execute_command(command)

if __name__ == "__main__":
    # Test case 1: List current directory
    print("Test Case 1: Current directory")
    execute_ls_command(".")
    
    # Test case 2: List home directory
    print("\\nTest Case 2: Home directory")
    execute_ls_command("~")
    
    # Test case 3: List with wildcard
    print("\\nTest Case 3: List with wildcard")
    execute_ls_command("*.py")
    
    # Test case 4: List parent directory
    print("\\nTest Case 4: Parent directory")
    execute_ls_command("..")
    
    # Test case 5: List /tmp directory
    print("\\nTest Case 5: /tmp directory")
    execute_ls_command("/tmp")
