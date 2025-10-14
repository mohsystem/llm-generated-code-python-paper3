
import os
from pathlib import Path
from typing import Optional

BASE_DIRECTORY = Path.cwd().resolve()

def read_file_contents(file_path: Optional[str]) -> str:
    if file_path is None or not file_path.strip():
        return "Error: File path cannot be None or empty"
    
    if len(file_path) > 4096:
        return "Error: File path too long"
    
    try:
        requested_path = (BASE_DIRECTORY / file_path).resolve()
        
        if not str(requested_path).startswith(str(BASE_DIRECTORY)):
            return "Error: Access denied - path outside allowed directory"
        
        if not requested_path.exists():
            return "Error: File does not exist"
        
        if not requested_path.is_file():
            return "Error: Path is not a regular file"
        
        if not os.access(requested_path, os.R_OK):
            return "Error: File is not readable"
        
        file_size = requested_path.stat().st_size
        if file_size > 10_000_000:
            return "Error: File too large (max 10MB)"
        
        with open(requested_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content
        
    except (ValueError, OSError) as e:
        return f"Error: {type(e).__name__}"
    except PermissionError:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def main() -> None:
    print("Test Case 1 - Valid file:")
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=BASE_DIRECTORY, suffix='.txt') as f:
            f.write("Hello, World!")
            temp_name = Path(f.name).name
        print(read_file_contents(temp_name))
        os.unlink(BASE_DIRECTORY / temp_name)
    except Exception:
        print("Failed to create test file")
    
    print("\\nTest Case 2 - Non-existent file:")
    print(read_file_contents("nonexistent_file.txt"))
    
    print("\\nTest Case 3 - Path traversal attempt:")
    print(read_file_contents("../../etc/passwd"))
    
    print("\\nTest Case 4 - None input:")
    print(read_file_contents(None))
    
    print("\\nTest Case 5 - Empty path:")
    print(read_file_contents(""))

if __name__ == "__main__":
    main()
