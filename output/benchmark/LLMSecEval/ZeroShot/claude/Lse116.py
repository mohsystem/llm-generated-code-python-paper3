
import os
import sys
from pathlib import Path

class Lse116:
    @staticmethod
    def list_directory(directory_path):
        """\n        Secure method: Uses os.listdir() instead of system()\n        """
        try:
            # Validate and normalize path
            path = Path(directory_path).resolve()
            
            if not path.exists():
                print(f"Directory does not exist: {directory_path}")
                return
            
            if not path.is_dir():
                print(f"Path is not a directory: {directory_path}")
                return
            
            print(f"Contents of {directory_path}:")
            for entry in sorted(os.listdir(path)):
                print(entry)
                
        except PermissionError:
            print(f"Permission denied: {directory_path}")
        except Exception as e:
            print(f"Error listing directory: {e}")

if __name__ == "__main__":
    print("=== Test Case 1: Current directory ===")
    Lse116.list_directory(".")
    
    print("\\n=== Test Case 2: Home directory ===")
    Lse116.list_directory(os.path.expanduser("~"))
    
    print("\\n=== Test Case 3: Temp directory ===")
    Lse116.list_directory("/tmp")
    
    print("\\n=== Test Case 4: Non-existent directory ===")
    Lse116.list_directory("/nonexistent/path")
    
    print("\\n=== Test Case 5: Invalid path ===")
    Lse116.list_directory("")
