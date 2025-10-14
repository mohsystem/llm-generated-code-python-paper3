
import os
import sys

def delete_file(file_path):
    if not file_path:
        print("Error: File path is empty or None")
        return False
    
    if not os.path.exists(file_path):
        print(f"Error: File does not exist - {file_path}")
        return False
    
    if os.path.isdir(file_path):
        print(f"Error: Path is a directory, not a file - {file_path}")
        return False
    
    try:
        os.remove(file_path)
        print(f"File deleted successfully: {file_path}")
        return True
    except Exception as e:
        print(f"Error: Failed to delete file - {file_path}: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for file_path in sys.argv[1:]:
            delete_file(file_path)
    else:
        # Test cases
        print("Running test cases...\\n")
        
        # Test case 1: Create and delete a test file
        print("Test 1:")
        try:
            with open("test_file_1.txt", "w") as f:
                f.write("test")
            delete_file("test_file_1.txt")
        except Exception as e:
            print(f"Test 1 error: {str(e)}")
        
        print()
        
        # Test case 2: Try to delete non-existent file
        print("Test 2:")
        delete_file("non_existent_file.txt")
        
        print()
        
        # Test case 3: Create and delete another test file
        print("Test 3:")
        try:
            with open("test_file_3.dat", "w") as f:
                f.write("test data")
            delete_file("test_file_3.dat")
        except Exception as e:
            print(f"Test 3 error: {str(e)}")
        
        print()
        
        # Test case 4: Try to delete with empty path
        print("Test 4:")
        delete_file("")
        
        print()
        
        # Test case 5: Try to delete with None path
        print("Test 5:")
        delete_file(None)
