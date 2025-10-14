
import re
import os

def match_lines(filename):
    matched_lines = []
    pattern = re.compile(r'^\\d+.*\\.$')
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.rstrip('\\n\\r')
                if pattern.match(line):
                    matched_lines.append(line)
    except IOError as e:
        print(f"Error reading file: {e}")
    
    return matched_lines

def main():
    # Create test files for demonstration
    test_files = ["test1.txt", "test2.txt", "test3.txt", "test4.txt", "test5.txt"]
    test_data = [
        ["123 This is a test.", "456 Another line.", "Not matching", "789 End with dot."],
        ["1 First line.", "Second line", "2 Third line.", "3 Fourth."],
        ["99 Single digit.", "100 Triple digits.", "No number here.", "5."],
        ["0 Zero start.", "abc", "42 The answer.", ""],
        ["7777 Multiple digits here.", "8888.", "Not starting with number.", "9 Final."]
    ]
    
    # Create test files
    for i, filename in enumerate(test_files):
        try:
            with open(filename, 'w') as file:
                for line in test_data[i]:
                    file.write(line + '\\n')
        except IOError as e:
            print(f"Error creating test file: {e}")
    
    # Test cases
    for i, filename in enumerate(test_files):
        print(f"Test Case {i + 1} - File: {filename}")
        results = match_lines(filename)
        print("Matched lines:")
        for line in results:
            print(f"  {line}")
        print()

if __name__ == "__main__":
    main()
