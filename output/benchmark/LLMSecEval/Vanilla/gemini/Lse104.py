import os

def create_file_and_write(filename, content):
    try:
        # 'w+' mode: opens for writing and reading.
        # Creates the file if it does not exist, otherwise truncates the file.
        with open(filename, 'w+') as f:
            f.write(content)
        return True
    except IOError as e:
        print(f"Error processing file {filename}: {e}")
        return False

def main():
    content = "important_config"
    
    print("--- Python Test Cases ---")
    
    # Test Case 1: Standard file creation
    file1 = "py_test1.cfg"
    print(f"\nTest 1: Writing to '{file1}'")
    if create_file_and_write(file1, content):
        print("Success.")
    else:
        print("Failed.")

    # Test Case 2: Different content
    file2 = "py_test2.dat"
    print(f"\nTest 2: Writing to '{file2}'")
    if create_file_and_write(file2, content + " for test 2"):
        print("Success.")
    else:
        print("Failed.")

    # Test Case 3: Path with non-existent directory (should fail)
    file3 = "data/py_test3.txt"
    print(f"\nTest 3: Writing to '{file3}'")
    if create_file_and_write(file3, content):
        print("Success.")
    else:
        print("Failed.")

    # Test Case 4: Empty filename (should fail)
    file4 = ""
    print(f"\nTest 4: Writing to empty filename")
    if create_file_and_write(file4, content):
        print("Success.")
    else:
        print("Failed.")

    # Test Case 5: Writing empty content
    file5 = "py_test5.log"
    print(f"\nTest 5: Writing an empty string to '{file5}'")
    if create_file_and_write(file5, ""):
        print("Success.")
    else:
        print("Failed.")

if __name__ == "__main__":
    main()