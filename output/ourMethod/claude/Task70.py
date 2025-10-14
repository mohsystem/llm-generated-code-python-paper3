
import sys
import os
from pathlib import Path
from typing import Optional

BASE_DIRECTORY = Path.cwd().resolve()

def read_file_content(file_path: str) -> str:
    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be None or empty")
    
    if len(file_path) > 4096:
        raise ValueError("File path exceeds maximum length")
    
    try:
        requested_path = Path(file_path)
        
        if requested_path.is_absolute():
            raise ValueError("Absolute paths are not allowed")
        
        absolute_path = (BASE_DIRECTORY / requested_path).resolve()
        
        if not str(absolute_path).startswith(str(BASE_DIRECTORY)):
            raise PermissionError("Access denied: path outside base directory")
        
        if not absolute_path.exists():
            raise FileNotFoundError(f"File does not exist: {file_path}")
        
        if absolute_path.is_symlink():
            raise PermissionError("Symbolic links are not allowed")
        
        if not absolute_path.is_file():
            raise ValueError(f"Path is not a regular file: {file_path}")
        
        file_size = absolute_path.stat().st_size
        if file_size > 10_485_760:
            raise ValueError("File size exceeds maximum limit (10MB)")
        
        with open(absolute_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content
        
    except (OSError, IOError) as e:
        raise RuntimeError(f"Error reading file: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {str(e)}")

def main():
    if len(sys.argv) < 2:
        print("Error: No file path provided", file=sys.stderr)
        print("Usage: python script.py <file_path>", file=sys.stderr)
        sys.exit(1)
    
    test_cases = [
        "test1.txt",
        "test2.txt",
        "test3.txt",
        "test4.txt",
        "test5.txt"
    ]
    
    print("Test cases:")
    for i, test_file in enumerate(test_cases, 1):
        print(f"\\nTest {i}: {test_file}")
        try:
            content = read_file_content(test_file)
            print(f"Content: {content}")
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
    
    print("\\n\\nActual execution with command line argument:")
    try:
        content = read_file_content(sys.argv[1])
        print(content)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
