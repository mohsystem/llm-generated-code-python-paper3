
import os
import subprocess
import platform

def display_file_contents(filename):
    try:
        if platform.system() == "Windows":
            command = f'type "{filename}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
        else:
            command = f'cat "{filename}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=__import__('sys').stderr)
            
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    # Create test files
    test_files = ["test1.txt", "test2.txt", "test3.txt", "test4.txt", "test5.txt"]
    test_contents = [
        "Hello World!",
        "This is test file 2.\\nWith multiple lines.",
        "Test file 3 contents",
        "Line 1\\nLine 2\\nLine 3",
        "Final test file"
    ]
    
    # Create test files
    for i, filename in enumerate(test_files):
        try:
            with open(filename, 'w') as f:
                f.write(test_contents[i])
        except Exception as e:
            print(f"Error creating test file: {e}")
    
    # Test cases
    for i, filename in enumerate(test_files):
        print(f"\\n--- Test Case {i + 1}: {filename} ---")
        display_file_contents(filename)
    
    # Clean up test files
    for filename in test_files:
        try:
            os.remove(filename)
        except:
            pass
