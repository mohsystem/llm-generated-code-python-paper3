import re
import os

def find_matching_lines(file_path):
    """
    Reads a file and returns a list of lines that start with a number 
    and end with a dot.
    """
    matching_lines = []
    # Raw string to avoid issues with backslashes.
    # ^\d matches a digit at the start of the line.
    # .* matches any character (except newline) zero or more times.
    # \.$ matches a literal dot at the end of the line.
    regex = r"^\d.*\.$"
    try:
        with open(file_path, 'r') as f:
            for line in f:
                # rstrip() removes trailing whitespace, including the newline character.
                clean_line = line.rstrip()
                if re.match(regex, clean_line):
                    matching_lines.append(clean_line)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return matching_lines

def run_test_case(file_name, content):
    """Helper function to run a single test case."""
    try:
        with open(file_name, 'w') as f:
            f.write(content)

        print(f"\n--- Testing with file: {file_name} ---")
        # repr() is a good way to show the string with escapes.
        print(f"Content:\n{repr(content)}")
        
        result = find_matching_lines(file_name)
        
        print("Result:")
        if not result:
            print("(No matching lines found)")
        else:
            for line in result:
                print(line)
        
        os.remove(file_name)
    except Exception as e:
        print(f"An error occurred during the test case: {e}")

if __name__ == "__main__":
    # Test Case 1: A file with a mix of valid and invalid lines.
    run_test_case("test_python_1.txt",
                  "1. This is a valid line.\n"
                  "This line is not valid.\n"
                  "2. This is also a valid line.\n"
                  "3 This line is not valid, no dot at the end\n"
                  "4.Valid line.\n"
                  "5.\n"
                  "Invalid line.\n"
                  "6. Another. valid. line.")

    # Test Case 2: An empty file.
    run_test_case("test_python_2.txt", "")

    # Test Case 3: A file with no matching lines.
    run_test_case("test_python_3.txt", "Hello world\nThis is a test\nNo lines match here")

    # Test Case 4: A file where all lines match.
    run_test_case("test_python_4.txt", "1. First.\n2. Second.\n3. Third.")
    
    # Test Case 5: A file with special characters and multiple digits.
    run_test_case("test_python_5.txt", "123. Special chars !@#$%^&*().\nAnother line\n45.Ends with a dot.")