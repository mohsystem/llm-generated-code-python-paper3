
import re
import sys
import os

def search_pattern_in_file(pattern_str, file_name):
    try:
        pattern = re.compile(pattern_str)
        with open(file_name, 'r') as file:
            content = file.read()
        
        print(f"Searching for pattern: {pattern_str} in file: {file_name}")
        matches = list(pattern.finditer(content))
        
        if not matches:
            print("No matches found.")
        else:
            for i, match in enumerate(matches, 1):
                print(f"Match {i}: {match.group()} at position {match.start()}")
            print(f"Total matches: {len(matches)}")
    
    except re.error as e:
        print(f"Invalid regex pattern: {e}")
    except FileNotFoundError:
        print(f"Error reading file: File not found - {file_name}")
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        search_pattern_in_file(sys.argv[1], sys.argv[2])
    else:
        print("Running test cases...\\n")
        
        # Create test files
        try:
            with open("test1.txt", "w") as f:
                f.write("Hello World! Hello Java!")
            with open("test2.txt", "w") as f:
                f.write("abc123def456ghi789")
            with open("test3.txt", "w") as f:
                f.write("email@example.com test@domain.org")
            with open("test4.txt", "w") as f:
                f.write("The quick brown fox jumps over the lazy dog")
            with open("test5.txt", "w") as f:
                f.write("Line1\\nLine2\\nLine3")
            
            # Test case 1
            print("Test 1:")
            search_pattern_in_file("Hello", "test1.txt")
            print()
            
            # Test case 2
            print("Test 2:")
            search_pattern_in_file(r"\\d+", "test2.txt")
            print()
            
            # Test case 3
            print("Test 3:")
            search_pattern_in_file(r"[a-z]+@[a-z]+\\.[a-z]+", "test3.txt")
            print()
            
            # Test case 4
            print("Test 4:")
            search_pattern_in_file(r"\\b\\w{3}\\b", "test4.txt")
            print()
            
            # Test case 5
            print("Test 5:")
            search_pattern_in_file(r"Line\\d", "test5.txt")
            print()
            
        except Exception as e:
            print(f"Error creating test files: {e}")
