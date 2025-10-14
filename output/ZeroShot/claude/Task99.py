
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
    # Test cases - creating test files
    test_files = ["test1.txt", "test2.txt", "test3.txt", "test4.txt", "test5.txt"]
    
    # Test case 1: Simple numbered list
    with open(test_files[0], 'w') as f:
        f.write("1 This is a sentence.\\n")
        f.write("2 Another line.\\n")
        f.write("Not matching\\n")
        f.write("3 Third line.\\n")
    
    # Test case 2: Multi-digit numbers
    with open(test_files[1], 'w') as f:
        f.write("123 Large number line.\\n")
        f.write("456 Another large number.\\n")
        f.write("No number here.\\n")
    
    # Test case 3: Lines without dots
    with open(test_files[2], 'w') as f:
        f.write("1 This has no dot\\n")
        f.write("2 This has a dot.\\n")
        f.write("3 No dot here\\n")
    
    # Test case 4: Mixed content
    with open(test_files[3], 'w') as f:
        f.write("99 Special characters !@#$.\\n")
        f.write("Start with text 100.\\n")
        f.write("0 Zero starts this.\\n")
    
    # Test case 5: Empty and edge cases
    with open(test_files[4], 'w') as f:
        f.write("1.\\n")
        f.write("2\\n")
        f.write(".\\n")
        f.write("12345 Multiple words here.\\n")
    
    # Execute test cases
    for i, test_file in enumerate(test_files):
        print(f"Test case {i + 1} - File: {test_file}")
        results = match_lines(test_file)
        print(f"Matched lines: {results}")
        print()

if __name__ == "__main__":
    main()
