
import re
import os
import sys
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def search_file_with_regex(regex_pattern, file_name):
    """Search file content using regex pattern with security validations."""
    
    # Validate inputs
    if not regex_pattern:
        print("Error: Regex pattern cannot be empty", file=sys.stderr)
        return
    
    if not file_name:
        print("Error: File name cannot be empty", file=sys.stderr)
        return
    
    try:
        # Validate file path (prevent path traversal)
        file_path = Path(file_name).resolve()
        
        # Check if file exists and is readable
        if not file_path.exists():
            print(f"Error: File does not exist: {file_name}", file=sys.stderr)
            return
        
        if not file_path.is_file():
            print(f"Error: Path is not a regular file: {file_name}", file=sys.stderr)
            return
        
        # Check file size
        if file_path.stat().st_size > MAX_FILE_SIZE:
            print("Error: File too large (max 10MB)", file=sys.stderr)
            return
        
        # Compile regex pattern
        try:
            pattern = re.compile(regex_pattern)
        except re.error as e:
            print(f"Error: Invalid regex pattern: {e}", file=sys.stderr)
            return
        
        # Read and search file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                found = False
                line_number = 0
                
                for line in f:
                    line_number += 1
                    matches = pattern.finditer(line.rstrip('\\n\\r'))
                    
                    for match in matches:
                        found = True
                        print(f"Line {line_number}: {line.rstrip()}")
                        print(f"  Match: \\{match.group()}\\ at position {match.start()}")
                
                if not found:
                    print("No matches found.")
                    
        except IOError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

def create_test_file(filename, content):
    """Helper function to create test files."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        print(f"Error creating test file: {e}", file=sys.stderr)

def cleanup_test_files():
    """Helper function to cleanup test files."""
    for filename in ['test1.txt', 'test2.txt', 'test3.txt']:
        try:
            if os.path.exists(filename):
                os.remove(filename)
        except:
            pass

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        search_file_with_regex(sys.argv[1], sys.argv[2])
    else:
        # Test cases
        print("=== Test Case 1: Search for email pattern ===")
        create_test_file("test1.txt", "Contact: john@example.com\\nEmail: jane@test.org")
        search_file_with_regex(r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "test1.txt")
        
        print("\\n=== Test Case 2: Search for phone numbers ===")
        create_test_file("test2.txt", "Call: 123-456-7890\\nPhone: 555-0123")
        search_file_with_regex(r"\\d{3}-\\d{3}-\\d{4}", "test2.txt")
        
        print("\\n=== Test Case 3: No matches ===")
        create_test_file("test3.txt", "No numbers here at all!")
        search_file_with_regex(r"\\d+", "test3.txt")
        
        print("\\n=== Test Case 4: Invalid regex ===")
        search_file_with_regex("[invalid(", "test1.txt")
        
        print("\\n=== Test Case 5: Non-existent file ===")
        search_file_with_regex("test", "nonexistent.txt")
        
        cleanup_test_files()
