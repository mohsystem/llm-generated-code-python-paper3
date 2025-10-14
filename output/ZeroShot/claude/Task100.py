
import re
import os
import sys

def search_pattern_in_file(pattern, filename):
    result = []
    
    try:
        # Validate input parameters
        if not pattern:
            return "Error: Pattern cannot be empty"
        if not filename:
            return "Error: Filename cannot be empty"
        
        # Validate filename and check file existence
        if not os.path.exists(filename):
            return "Error: File does not exist"
        if not os.path.isfile(filename):
            return "Error: Not a regular file"
        if not os.access(filename, os.R_OK):
            return "Error: File is not readable"
        
        # Check file size (max 10MB)
        file_size = os.path.getsize(filename)
        if file_size > 10 * 1024 * 1024:
            return "Error: File too large (max 10MB)"
        
        # Compile the regular expression
        try:
            regex_pattern = re.compile(pattern)
        except re.error as e:
            return f"Error: Invalid regex pattern - {str(e)}"
        
        # Read and search file content
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        matches = list(regex_pattern.finditer(content))
        match_count = 0
        
        for match in matches[:1000]:  # Limit to 1000 matches
            result.append(f"Match found at position {match.start()}: {match.group()}")
            match_count += 1
        
        if match_count == 0:
            result.append("No matches found")
        else:
            result.append(f"Total matches: {match_count}")
        
    except IOError as e:
        return f"Error reading file: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"
    
    return '\\n'.join(result)


def create_test_file(filename, content):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        print(f"Error creating test file: {e}")


def delete_test_file(filename):
    try:
        if os.path.exists(filename):
            os.remove(filename)
    except Exception as e:
        print(f"Error deleting test file: {e}")


def main():
    # Test cases
    print("=== Test Case 1: Search for word pattern ===")
    create_test_file("test1.txt", "Hello world! Hello Java programming.")
    print(search_pattern_in_file("Hello", "test1.txt"))
    
    print("\\n=== Test Case 2: Search for email pattern ===")
    create_test_file("test2.txt", "Contact: user@example.com or admin@test.org")
    print(search_pattern_in_file(r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "test2.txt"))
    
    print("\\n=== Test Case 3: Search for digit pattern ===")
    create_test_file("test3.txt", "The numbers are 123, 456, and 789.")
    print(search_pattern_in_file(r"\\d+", "test3.txt"))
    
    print("\\n=== Test Case 4: Invalid pattern ===")
    print(search_pattern_in_file("[invalid(", "test1.txt"))
    
    print("\\n=== Test Case 5: Non-existent file ===")
    print(search_pattern_in_file("test", "nonexistent.txt"))
    
    # Cleanup
    delete_test_file("test1.txt")
    delete_test_file("test2.txt")
    delete_test_file("test3.txt")


if __name__ == "__main__":
    main()
