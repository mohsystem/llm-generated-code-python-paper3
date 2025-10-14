
import os
import sys
from pathlib import Path

def delete_file(file_path):
    if not file_path or not file_path.strip():
        print("Error: File path cannot be null or empty")
        return False
    
    try:
        path = Path(file_path).resolve()
        
        if not path.exists():
            print(f"Error: File does not exist: {file_path}")
            return False
        
        if not path.is_file():
            print(f"Error: Path is not a file: {file_path}")
            return False
        
        if not os.access(path, os.W_OK):
            print(f"Error: No permission to delete file: {file_path}")
            return False
        
        path.unlink()
        print(f"File deleted successfully: {file_path}")
        return True
        
    except PermissionError:
        print("Error: Permission denied - insufficient permissions")
        return False
    except OSError as e:
        print("Error: OS error occurred while deleting file")
        return False
    except Exception as e:
        print("Error: Unexpected error occurred")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python Task69.py <file_path>")
        
        print("\\n=== Running Test Cases ===\\n")
        
        import tempfile
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                test_file1 = f.name
            print("Test 1: Delete existing file")
            delete_file(test_file1)
            
            print("\\nTest 2: Delete non-existent file")
            delete_file("non_existent_file.txt")
            
            print("\\nTest 3: Delete with None path")
            delete_file(None)
            
            print("\\nTest 4: Delete with empty path")
            delete_file("")
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                test_file5 = f.name
            print("\\nTest 5: Delete valid file with normalized path")
            delete_file(test_file5)
            
        except Exception as e:
            print("Error creating test files")
        
        return
    
    delete_file(sys.argv[1])

if __name__ == "__main__":
    main()
