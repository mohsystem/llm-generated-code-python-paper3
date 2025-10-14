import os

def read_file_and_print(file_path):
    """
    Reads a file specified by the file path and prints its contents to the console.
    
    :param file_path: The path to the file to be read.
    """
    print(f"Reading file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content:
                print("(File is empty)")
            else:
                # Use print() which adds a newline, so no need for end=''
                # if the file content itself doesn't end with a newline
                print(content, end='')
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")

def create_test_file(filename, content):
    """Helper function to create a test file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        print(f"Failed to create test file {filename}: {e}")

# Main execution block with test cases
if __name__ == "__main__":
    # --- Test Case 1: Read a simple, single-line file ---
    print("--- Test Case 1: Simple File ---")
    file1 = "py_test1.txt"
    create_test_file(file1, "Hello, World from Python!")
    read_file_and_print(file1)
    print("\n-------------------------------------\n")

    # --- Test Case 2: Read a multi-line file ---
    print("--- Test Case 2: Multi-line File ---")
    file2 = "py_test2.txt"
    create_test_file(file2, "This is line one.\nThis is line two.\nAnd this is the third line.")
    read_file_and_print(file2)
    print("\n-------------------------------------\n")

    # --- Test Case 3: Read an empty file ---
    print("--- Test Case 3: Empty File ---")
    file3 = "py_test3_empty.txt"
    create_test_file(file3, "")
    read_file_and_print(file3)
    print("\n-------------------------------------\n")

    # --- Test Case 4: Attempt to read a non-existent file ---
    print("--- Test Case 4: Non-existent File ---")
    read_file_and_print("nonexistentfile.txt")
    print("-------------------------------------\n")

    # --- Test Case 5: Read a file with special characters ---
    print("--- Test Case 5: Special Characters File ---")
    file4 = "py_test4_special.txt"
    create_test_file(file4, "Special chars: ñ, é, ö, ü, ç, α, β, γ. 😊🎉")
    read_file_and_print(file4)
    print("\n-------------------------------------\n")
    
    # Cleanup test files
    os.remove(file1)
    os.remove(file2)
    os.remove(file3)
    os.remove(file4)