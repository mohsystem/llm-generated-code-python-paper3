
import re
import os
from pathlib import Path
from typing import List

MAX_LINE_LENGTH = 10000
MAX_LINES = 100000
LINE_PATTERN = re.compile(r'^\\d+.*\\.$')

def match_lines(base_dir: str, file_name: str) -> List[str]:
    if not base_dir or not file_name:
        raise ValueError("Base directory and file name must not be empty")
    
    matched_lines = []
    
    try:
        base_path = Path(base_dir).resolve()
        file_path = (base_path / file_name).resolve()
        
        if not str(file_path).startswith(str(base_path)):
            raise SecurityError("Path traversal attempt detected")
        
        if not file_path.is_file():
            raise ValueError("Not a regular file")
        
        if file_path.is_symlink():
            raise SecurityError("Symbolic links are not allowed")
        
        line_count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_count += 1
                if line_count > MAX_LINES:
                    raise ValueError("File exceeds maximum line limit")
                
                line = line.rstrip('\\n\\r')
                
                if len(line) > MAX_LINE_LENGTH:
                    continue
                
                if LINE_PATTERN.match(line):
                    matched_lines.append(line)
    
    except IOError as e:
        raise RuntimeError(f"Error reading file: {e}")
    
    return matched_lines

def main():
    import tempfile
    import shutil
    
    test_dir = tempfile.mkdtemp()
    
    try:
        # Test case 1: Valid lines starting with numbers and ending with dot
        test_file1 = os.path.join(test_dir, "test1.txt")
        with open(test_file1, 'w', encoding='utf-8') as f:
            f.write("123 This is a test.\\n456 Another line.\\nNo number here.\\n789 Valid.")
        result1 = match_lines(test_dir, "test1.txt")
        print(f"Test 1: {result1}")
        
        # Test case 2: Mixed content
        test_file2 = os.path.join(test_dir, "test2.txt")
        with open(test_file2, 'w', encoding='utf-8') as f:
            f.write("1 Start.\\n2No space but valid.\\nNot valid\\n3 End.")
        result2 = match_lines(test_dir, "test2.txt")
        print(f"Test 2: {result2}")
        
        # Test case 3: Empty file
        test_file3 = os.path.join(test_dir, "test3.txt")
        with open(test_file3, 'w', encoding='utf-8') as f:
            f.write("")
        result3 = match_lines(test_dir, "test3.txt")
        print(f"Test 3: {result3}")
        
        # Test case 4: No matching lines
        test_file4 = os.path.join(test_dir, "test4.txt")
        with open(test_file4, 'w', encoding='utf-8') as f:
            f.write("No match here\\nAnother no match\\n")
        result4 = match_lines(test_dir, "test4.txt")
        print(f"Test 4: {result4}")
        
        # Test case 5: All lines match
        test_file5 = os.path.join(test_dir, "test5.txt")
        with open(test_file5, 'w', encoding='utf-8') as f:
            f.write("0 Zero.\\n99 Ninety nine.\\n42 Answer.")
        result5 = match_lines(test_dir, "test5.txt")
        print(f"Test 5: {result5}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
