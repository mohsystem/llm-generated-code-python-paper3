
import os
import sys
from pathlib import Path

def delete_file(file_path):
    if not file_path or not file_path.strip():
        return "Error: File path cannot be null or empty"
    
    try:
        # Sanitize the file path to prevent path traversal attacks
        path = Path(file_path).resolve()
        
        # Check if file exists
        if not path.exists():
            return f"Error: File does not exist: {file_path}"
        
        # Check if it's a file (not a directory)\n        if not path.is_file():\n            return f"Error: Path is not a file: {file_path}"\n        \n        # Check if file is writable\n        if not os.access(path, os.W_OK):\n            return f"Error: No permission to delete file: {file_path}"\n        \n        # Delete the file\n        os.remove(path)\n        return f"Success: File deleted successfully: {file_path}"\n        \n    except PermissionError:\n        return f"Error: Permission denied: {file_path}"\n    except Exception as e:\n        return f"Error: {str(e)}"\n\ndef main():\n    # Test cases\n    print("Test Case 1: Empty file path")\n    print(delete_file(""))\n    print()\n    \n    print("Test Case 2: None file path")\n    print(delete_file(None))\n    print()\n    \n    print("Test Case 3: Non-existent file")\n    print(delete_file("nonexistent_file.txt"))\n    print()\n    \n    print("Test Case 4: Create and delete a test file")\n    try:\n        test_file = "test_file_to_delete.txt"\n        with open(test_file, 'w') as f:
            f.write("test content")
        print(delete_file(test_file))
    except Exception as e:
        print(f"Error creating test file: {str(e)}")
    print()
    
    print("Test Case 5: Command line argument")
    if len(sys.argv) > 1:
        print(delete_file(sys.argv[1]))
    else:
        print("No command line argument provided")

if __name__ == "__main__":
    main()
