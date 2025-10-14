import re
import os

def find_matching_lines(file_path):
    """
    Reads a file and returns a list of lines that start with numbers and end with a dot.

    Args:
        file_path (str): The path to the file.

    Returns:
        list: A list of strings, where each string is a matching line.
    """
    matching_lines = []
    # Regex: r"^\d+ -> starts with one or more digits
    #         .*   -> followed by any character, zero or more times
    #         \.   -> a literal dot
    #         $    -> end of the line"
    # Using a raw string (r"...") is best practice for regex in Python.
    regex = r"^\d+.*.$"
    
    try:
        # Using 'with' statement ensures the file is properly closed
        with open(file_path, 'r') as f:
            for line in f:
                # re.match checks for a match only at the beginning of the string.
                # We also strip the trailing newline character for clean output.
                stripped_line = line.strip()
                if re.match(regex, stripped_line):
                    matching_lines.append(stripped_line)
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
    except IOError as e:
        print(f"Error reading file: {e}")
        
    return matching_lines

if __name__ == "__main__":
    test_file_name = "test_Task99.txt"

    # Create a test file with some content
    try:
        with open(test_file_name, 'w') as writer:
            writer.write("1. This is the first test case.\n")
            writer.write("This line does not start with a number.\n")
            writer.write("2. Second test case.\n")
            writer.write("3 A line without a dot at the end\n")
            writer.write("4. Test case three is here.\n")
            writer.write("Another non-matching line.\n")
            writer.write("55. Test case four.\n")
            writer.write("99999. Final test case.\n")
            writer.write("The end.\n")
            writer.write("6 is not a match either\n")
    except IOError as e:
        print(f"Error creating test file: {e}")
        exit()

    print(f"--- Reading from file: {test_file_name} ---")
    matched = find_matching_lines(test_file_name)

    print(f"Found {len(matched)} matching lines:")
    for line in matched:
        print(line)

    # Clean up the test file
    os.remove(test_file_name)