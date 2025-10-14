
from typing import List, Tuple
import os
from pathlib import Path


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_LINE_LENGTH = 10000
KEY_VALUE_SEPARATOR = "="


class KeyValueRecord:
    def __init__(self, key: str, value: str):
        if key is None or value is None:
            raise ValueError("Key and value cannot be None")
        self.key = key
        self.value = value
    
    def __lt__(self, other: 'KeyValueRecord') -> bool:
        return self.key < other.key
    
    def __str__(self) -> str:
        return f"{self.key}{KEY_VALUE_SEPARATOR}{self.value}"
    
    def __repr__(self) -> str:
        return self.__str__()


def read_and_sort_records(base_dir: str, filename: str) -> List[KeyValueRecord]:
    """\n    Reads key-value records from a file and returns them sorted by key.\n    \n    Args:\n        base_dir: Base directory path\n        filename: Name of the file to read\n        \n    Returns:\n        List of KeyValueRecord objects sorted by key\n        \n    Raises:\n        ValueError: If inputs are invalid\n        FileNotFoundError: If file doesn't exist\n        SecurityException: If path traversal is detected\n        IOError: If file operations fail\n    """
    if not base_dir or not filename:
        raise ValueError("Base directory and filename cannot be empty")
    
    # Normalize and validate paths
    base_path = Path(base_dir).resolve()
    file_path = (base_path / filename).resolve()
    
    # Ensure file is within base directory
    try:
        file_path.relative_to(base_path)
    except ValueError:
        raise SecurityError("Path traversal detected: file must be within base directory")
    
    # Check if file exists and is a regular file
    if not file_path.exists():
        raise FileNotFoundError(f"File does not exist: {filename}")
    
    if not file_path.is_file():
        raise IOError(f"Path is not a regular file: {filename}")
    
    # Check for symlinks
    if file_path.is_symlink():
        raise IOError(f"Symlinks are not allowed: {filename}")
    
    # Check file size
    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise IOError(f"File size exceeds maximum allowed: {file_size}")
    
    records: List[KeyValueRecord] = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
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
                    raise IOError(f"Invalid key-value format at line {line_number}: {line}")
                
                key = line[:separator_index].strip()
                value = line[separator_index + 1:].strip()
                
                if not key:
                    raise IOError(f"Empty key at line {line_number}")
                
                records.append(KeyValueRecord(key, value))
                
    except IOError as e:
        raise IOError(f"Error reading file: {str(e)}")
    
    # Sort records by key
    records.sort()
    
    return records


class SecurityError(Exception):
    pass


def main():
    import tempfile
    
    # Test case 1: Normal key-value pairs
    try:
        with tempfile.TemporaryDirectory() as base_dir:
            test_file1 = Path(base_dir) / "test1.txt"
            test_file1.write_text("zebra=animal\\napple=fruit\\nbanana=fruit\\n", encoding='utf-8')
            result1 = read_and_sort_records(base_dir, "test1.txt")
            print("Test 1 - Normal sorting:")
            for record in result1:
                print(record)
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: With comments and empty lines
    try:
        with tempfile.TemporaryDirectory() as base_dir:
            test_file2 = Path(base_dir) / "test2.txt"
            test_file2.write_text("# Comment line\\n\\ndog=pet\\ncat=pet\\n\\n", encoding='utf-8')
            result2 = read_and_sort_records(base_dir, "test2.txt")
            print("\\nTest 2 - With comments:")
            for record in result2:
                print(record)
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Numeric keys
    try:
        with tempfile.TemporaryDirectory() as base_dir:
            test_file3 = Path(base_dir) / "test3.txt"
            test_file3.write_text("3=three\\n1=one\\n2=two\\n", encoding='utf-8')
            result3 = read_and_sort_records(base_dir, "test3.txt")
            print("\\nTest 3 - Numeric keys:")
            for record in result3:
                print(record)
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Values with spaces
    try:
        with tempfile.TemporaryDirectory() as base_dir:
            test_file4 = Path(base_dir) / "test4.txt"
            test_file4.write_text("key1=value with spaces\\nakey=another value\\n", encoding='utf-8')
            result4 = read_and_sort_records(base_dir, "test4.txt")
            print("\\nTest 4 - Values with spaces:")
            for record in result4:
                print(record)
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: File not found
    try:
        with tempfile.TemporaryDirectory() as base_dir:
            result5 = read_and_sort_records(base_dir, "nonexistent.txt")
            print("\\nTest 5 - File not found: FAILED (should throw exception)")
    except Exception as e:
        print(f"\\nTest 5 - File not found: PASSED - {e}")


if __name__ == "__main__":
    main()
