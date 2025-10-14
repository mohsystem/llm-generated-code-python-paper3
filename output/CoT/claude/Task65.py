
import os
import re
from pathlib import Path

class Task65:
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]+$')
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
    
    @staticmethod
    def read_file_securely(filename):
        if filename is None or not filename.strip():
            return "Error: Filename cannot be null or empty"
        
        try:
            # Sanitize filename - prevent path traversal
            sanitized_filename = os.path.basename(filename)
            
            # Validate filename format
            if not Task65.SAFE_FILENAME_PATTERN.match(sanitized_filename):
                return "Error: Invalid filename format. Only alphanumeric, dots, hyphens, and underscores allowed"
            
            # Resolve to absolute path and check if file exists
            file_path = Path(sanitized_filename).resolve()
            
            if not file_path.exists():
                return "Error: File does not exist"
            
            if not file_path.is_file():
                return "Error: Not a regular file"
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > Task65.MAX_FILE_SIZE:
                return "Error: File size exceeds maximum allowed size"
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except PermissionError:
            return "Error: Permission denied to read file"
        except OSError as e:
            return f"Error: Unable to read file - {str(e)}"
        except UnicodeDecodeError:
            return "Error: File encoding is not UTF-8"
        except Exception as e:
            return f"Error: Unexpected error - {str(e)}"

def main():
    # Test case 1: Valid file
    print("Test 1 - Valid file:")
    print(Task65.read_file_securely("test.txt"))
    print()
    
    # Test case 2: None filename
    print("Test 2 - None filename:")
    print(Task65.read_file_securely(None))
    print()
    
    # Test case 3: Empty filename
    print("Test 3 - Empty filename:")
    print(Task65.read_file_securely(""))
    print()
    
    # Test case 4: Path traversal attempt
    print("Test 4 - Path traversal attempt:")
    print(Task65.read_file_securely("../etc/passwd"))
    print()
    
    # Test case 5: Non-existent file
    print("Test 5 - Non-existent file:")
    print(Task65.read_file_securely("nonexistent.txt"))

if __name__ == "__main__":
    main()
