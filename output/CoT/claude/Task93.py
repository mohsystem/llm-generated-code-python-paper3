
import os
from typing import List, Tuple

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

class KeyValuePair:
    def __init__(self, key: str, value: str):
        self.key = key if key is not None else ""
        self.value = value if value is not None else ""
    
    def __lt__(self, other):
        return self.key < other.key
    
    def __str__(self):
        return f"{self.key}={self.value}"
    
    def __repr__(self):
        return self.__str__()

def read_and_sort_key_value_file(file_path: str) -> List[KeyValuePair]:
    records = []
    
    if not file_path or not file_path.strip():
        print("Invalid file path", file=__import__('sys').stderr)
        return records
    
    # Normalize path to prevent path traversal
    file_path = os.path.normpath(file_path)
    
    try:
        # Check file size
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            print("File size exceeds maximum allowed size", file=__import__('sys').stderr)
            return records
        
        with open(file_path, 'r', encoding='utf-8') as file:
            line_number = 0
            
            for line in file:
                line_number += 1
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse key-value pair
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    records.append(KeyValuePair(key, value))
                else:
                    print(f"Malformed line {line_number}: {line}", file=__import__('sys').stderr)
        
        # Sort records by key
        records.sort()
        
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}", file=__import__('sys').stderr)
    except PermissionError:
        print(f"Error: Permission denied - {file_path}", file=__import__('sys').stderr)
    except IOError as e:
        print(f"Error reading file: {e}", file=__import__('sys').stderr)
    except Exception as e:
        print(f"Unexpected error: {e}", file=__import__('sys').stderr)
    
    return records

def main():
    # Test case 1: Create and read a valid file
    print("Test 1 - Valid file:")
    test_file1 = "test1.txt"
    try:
        with open(test_file1, 'w') as f:
            f.write("name=John\\n")
            f.write("age=30\\n")
            f.write("city=NewYork\\n")
            f.write("country=USA\\n")
        
        result1 = read_and_sort_key_value_file(test_file1)
        for pair in result1:
            print(pair)
        
        os.remove(test_file1)
        print()
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: File with comments and empty lines
    print("Test 2 - File with comments:")
    test_file2 = "test2.txt"
    try:
        with open(test_file2, 'w') as f:
            f.write("# This is a comment\\n")
            f.write("zebra=animal\\n")
            f.write("\\n")
            f.write("apple=fruit\\n")
            f.write("banana=fruit\\n")
        
        result2 = read_and_sort_key_value_file(test_file2)
        for pair in result2:
            print(pair)
        
        os.remove(test_file2)
        print()
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: File with malformed lines
    print("Test 3 - Malformed lines:")
    test_file3 = "test3.txt"
    try:
        with open(test_file3, 'w') as f:
            f.write("valid=line\\n")
            f.write("invalid line without equals\\n")
            f.write("another=valid\\n")
        
        result3 = read_and_sort_key_value_file(test_file3)
        for pair in result3:
            print(pair)
        
        os.remove(test_file3)
        print()
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Non-existent file
    print("Test 4 - Non-existent file:")
    result4 = read_and_sort_key_value_file("nonexistent.txt")
    print(f"Records found: {len(result4)}")
    print()
    
    # Test case 5: Empty file path
    print("Test 5 - Empty file path:")
    result5 = read_and_sort_key_value_file("")
    print(f"Records found: {len(result5)}")

if __name__ == "__main__":
    main()
