
from pathlib import Path
from typing import List
import os

BASE_DIR = "."

def transpose_file(filename: str) -> str:
    if not filename or not filename.strip():
        raise ValueError("Filename cannot be null or empty")
    
    base_path = Path(BASE_DIR).resolve()
    file_path = (base_path / filename).resolve()
    
    if not file_path.is_relative_to(base_path):
        raise SecurityError("Path traversal attempt detected")
    
    if not file_path.exists():
        raise ValueError(f"File does not exist: {filename}")
    
    if not file_path.is_file():
        raise ValueError(f"Path is not a regular file: {filename}")
    
    rows: List[List[str]] = []
    max_cols = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\\n\\r')
                if not line:
                    continue
                fields = line.split(' ')
                rows.append(fields)
                max_cols = max(max_cols, len(fields))
    except IOError as e:
        raise RuntimeError(f"Error reading file: {e}")
    
    if not rows:
        return ""
    
    result = []
    for col in range(max_cols):
        row_values = []
        for row in rows:
            if col < len(row):
                row_values.append(row[col])
        result.append(' '.join(row_values))
    
    return '\\n'.join(result)

def main():
    try:
        test_file1 = "test1.txt"
        with open(test_file1, 'w', encoding='utf-8') as f:
            f.write("name age\\nalice 21\\nryan 30")
        print("Test 1:")
        print(transpose_file(test_file1))
        print()
        
        test_file2 = "test2.txt"
        with open(test_file2, 'w', encoding='utf-8') as f:
            f.write("a b c\\nd e f")
        print("Test 2:")
        print(transpose_file(test_file2))
        print()
        
        test_file3 = "test3.txt"
        with open(test_file3, 'w', encoding='utf-8') as f:
            f.write("x\\ny\\nz")
        print("Test 3:")
        print(transpose_file(test_file3))
        print()
        
        test_file4 = "test4.txt"
        with open(test_file4, 'w', encoding='utf-8') as f:
            f.write("one two three four")
        print("Test 4:")
        print(transpose_file(test_file4))
        print()
        
        test_file5 = "test5.txt"
        with open(test_file5, 'w', encoding='utf-8') as f:
            f.write("hello world\\nfoo bar\\ntest case")
        print("Test 5:")
        print(transpose_file(test_file5))
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
