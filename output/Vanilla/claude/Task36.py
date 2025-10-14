
def read_file_contents(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read()
        return content
    except IOError as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Test case 1: Create and read a simple text file
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello, World!\\n")
            f.write("This is test file 1.\\n")
        print("Test Case 1:")
        print(read_file_contents("test1.txt"))
    except Exception as e:
        print(f"Error in test case 1: {str(e)}")
    
    # Test case 2: Create and read a file with multiple lines
    try:
        with open("test2.txt", "w") as f:
            f.write("Line 1\\n")
            f.write("Line 2\\n")
            f.write("Line 3\\n")
        print("Test Case 2:")
        print(read_file_contents("test2.txt"))
    except Exception as e:
        print(f"Error in test case 2: {str(e)}")
    
    # Test case 3: Empty file
    try:
        with open("test3.txt", "w") as f:
            pass
        print("Test Case 3 (Empty file):")
        print(read_file_contents("test3.txt"))
    except Exception as e:
        print(f"Error in test case 3: {str(e)}")
    
    # Test case 4: File with special characters
    try:
        with open("test4.txt", "w") as f:
            f.write("Special chars: @#$%^&*()\\n")
            f.write("Numbers: 123456789\\n")
        print("Test Case 4:")
        print(read_file_contents("test4.txt"))
    except Exception as e:
        print(f"Error in test case 4: {str(e)}")
    
    # Test case 5: Non-existent file
    print("Test Case 5 (Non-existent file):")
    print(read_file_contents("nonexistent.txt"))
