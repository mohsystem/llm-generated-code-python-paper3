
import re
import os
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def match_lines(file_path):
    matched_lines = []
    
    if not file_path or not isinstance(file_path, str):
        print("Error: File path must be a non-empty string", file=__import__('sys').stderr)
        return matched_lines
    
    try:
        # Resolve path to prevent path traversal attacks
        resolved_path = Path(file_path).resolve()
        
        # Check if file exists
        if not resolved_path.exists():
            print(f"Error: File does not exist: {file_path}", file=__import__('sys').stderr)
            return matched_lines
        
        # Check file size to prevent DOS attacks
        file_size = resolved_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            print("Error: File size exceeds maximum allowed size", file=__import__('sys').stderr)
            return matched_lines
        
        # Regular expression pattern: starts with digit(s), ends with dot
        pattern = re.compile(r'^\\d+.*\\.$')
        
        with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.rstrip('\\n\\r')
                if pattern.match(line):
                    matched_lines.append(line)
    
    except IOError as e:
        print(f"Error reading file: {e}", file=__import__('sys').stderr)
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    
    return matched_lines


def main():
    # Test case 1: File with numbered lines
    test_file1 = "test1.txt"
    try:
        with open(test_file1, 'w') as f:
            f.write("1 This is line one.\\n2 Second line.\\n3 Third line.")
        print("Test 1 - File with numbered lines:")
        result1 = match_lines(test_file1)
        for line in result1:
            print(line)
        os.remove(test_file1)
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Mixed content
    test_file2 = "test2.txt"
    try:
        with open(test_file2, 'w') as f:
            f.write("123 Start with number.\\nNo number start.\\n456 Another one.")
        print("\\nTest 2 - Mixed content:")
        result2 = match_lines(test_file2)
        for line in result2:
            print(line)
        os.remove(test_file2)
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: No matching lines
    test_file3 = "test3.txt"
    try:
        with open(test_file3, 'w') as f:
            f.write("No numbers here\\nAnother line without numbers")
        print("\\nTest 3 - No matching lines:")
        result3 = match_lines(test_file3)
        print(f"Matched lines: {len(result3)}")
        os.remove(test_file3)
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Lines ending without dot
    test_file4 = "test4.txt"
    try:
        with open(test_file4, 'w') as f:
            f.write("1 Line with dot.\\n2 Line without dot\\n3 Another with dot.")
        print("\\nTest 4 - Lines with and without ending dot:")
        result4 = match_lines(test_file4)
        for line in result4:
            print(line)
        os.remove(test_file4)
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Invalid file path
    print("\\nTest 5 - Invalid file path:")
    result5 = match_lines("nonexistent_file.txt")
    print(f"Matched lines: {len(result5)}")


if __name__ == "__main__":
    main()
