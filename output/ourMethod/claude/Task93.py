
from typing import List, Tuple
import os
from pathlib import Path


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_LINE_LENGTH = 10000
KEY_VALUE_SEPARATOR = "="


def read_and_sort_key_value_file(file_path: str, base_directory: Path) -> List[Tuple[str, str]]:
    if not file_path or not isinstance(file_path, str):
        raise ValueError("File path cannot be None or empty")
    
    if base_directory is None or not isinstance(base_directory, Path):
        raise ValueError("Base directory must be a valid Path object")
    
    # Normalize and validate path
    requested_path = (base_directory / file_path).resolve()
    base_resolved = base_directory.resolve()
    
    if not str(requested_path).startswith(str(base_resolved)):
        raise SecurityError("Path traversal attempt detected")
    
    # Check if file exists and is a regular file
    if not requested_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not requested_path.is_file() or requested_path.is_symlink():
        raise IOError("Not a regular file or symlink detected")
    
    # Check file size
    file_size = requested_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise IOError("File size exceeds maximum allowed size")
    
    key_value_dict = {}
    
    with open(requested_path, 'r', encoding='utf-8') as file:
        line_number = 0
        
        for line in file:
            line_number += 1
            
            if len(line) > MAX_LINE_LENGTH:
                raise IOError(f"Line {line_number} exceeds maximum length")
            
            # Skip empty lines and comments
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse key-value pair
            separator_index = line.find(KEY_VALUE_SEPARATOR)
            if separator_index <= 0 or separator_index >= len(line) - 1:
                raise ValueError(f"Invalid key-value format at line {line_number}")
            
            key = line[:separator_index].strip()
            value = line[separator_index + 1:].strip()
            
            if not key:
                raise ValueError(f"Empty key at line {line_number}")
            
            key_value_dict[key] = value
    
    # Sort by key and return as list of tuples
    return sorted(key_value_dict.items(), key=lambda x: x[0])


def main():
    import tempfile
    
    try:
        base_dir = Path(tempfile.gettempdir())
        
        # Test case 1: Normal key-value pairs
        test_file1 = base_dir / "test1.txt"
        test_file1.write_text("zebra=animal\\napple=fruit\\ncar=vehicle\\n", encoding='utf-8')
        result1 = read_and_sort_key_value_file("test1.txt", base_dir)
        print(f"Test 1: {result1}")
        
        # Test case 2: With comments and empty lines
        test_file2 = base_dir / "test2.txt"
        test_file2.write_text("# Comment\\n\\nkey2=value2\\nkey1=value1\\n", encoding='utf-8')
        result2 = read_and_sort_key_value_file("test2.txt", base_dir)
        print(f"Test 2: {result2}")
        
        # Test case 3: Values with spaces
        test_file3 = base_dir / "test3.txt"
        test_file3.write_text("name=John Doe\\ncity=New York\\nage=30\\n", encoding='utf-8')
        result3 = read_and_sort_key_value_file("test3.txt", base_dir)
        print(f"Test 3: {result3}")
        
        # Test case 4: Single entry
        test_file4 = base_dir / "test4.txt"
        test_file4.write_text("single=value\\n", encoding='utf-8')
        result4 = read_and_sort_key_value_file("test4.txt", base_dir)
        print(f"Test 4: {result4}")
        
        # Test case 5: Multiple entries with numeric keys
        test_file5 = base_dir / "test5.txt"
        test_file5.write_text("3=three\\n1=one\\n2=two\\n", encoding='utf-8')
        result5 = read_and_sort_key_value_file("test5.txt", base_dir)
        print(f"Test 5: {result5}")
        
        # Cleanup
        test_file1.unlink(missing_ok=True)
        test_file2.unlink(missing_ok=True)
        test_file3.unlink(missing_ok=True)
        test_file4.unlink(missing_ok=True)
        test_file5.unlink(missing_ok=True)
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
