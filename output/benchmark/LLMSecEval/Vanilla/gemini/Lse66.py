import os
import shutil

def save_pdf(source_file_path):
    """
    Simulates saving an uploaded PDF file to an 'uploads' directory.
    
    :param source_file_path: The path to the source PDF file.
    :return: True if the file was saved successfully, False otherwise.
    """
    if not source_file_path or not isinstance(source_file_path, str):
        print("Error: Source file path is invalid.")
        return False
    
    # 1. Check if source file exists and is a regular file
    if not os.path.isfile(source_file_path):
        print(f"Error: Source file does not exist or is not a regular file: {source_file_path}")
        return False
    
    # 2. Check if the file is a PDF (case-insensitive)
    if not source_file_path.lower().endswith('.pdf'):
        print(f"Error: File is not a PDF: {source_file_path}")
        return False
    
    # 3. Create the 'uploads' directory if it doesn't exist
    upload_dir_name = "uploads"
    try:
        os.makedirs(upload_dir_name, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create directory '{upload_dir_name}'. {e}")
        return False
        
    # 4. Copy the file to the uploads directory
    try:
        file_name = os.path.basename(source_file_path)
        destination_path = os.path.join(upload_dir_name, file_name)
        shutil.copy(source_file_path, destination_path)
        print(f"Successfully saved '{source_file_path}' to '{destination_path}'")
        return True
    except (IOError, shutil.Error) as e:
        print(f"Error: Could not save file '{source_file_path}'. {e}")
        return False

def main():
    """Main function to set up environment and run test cases."""

    def create_dummy_file(filename, content):
        try:
            with open(filename, 'w') as f:
                f.write(content)
        except IOError as e:
            print(f"Failed to create dummy file: {filename}. Error: {e}")
            
    # Setup test environment by creating some dummy files
    print("--- Setting up test environment ---")
    create_dummy_file("test1.pdf", "This is the content of PDF 1.")
    create_dummy_file("test2.pdf", "This is the content of PDF 2.")
    create_dummy_file("test3.txt", "This is a text file, not a PDF.")
    create_dummy_file("test4.pdf", "This is PDF 4, used to test when the uploads dir already exists.")

    test_cases = [
        "test1.pdf",          # Case 1: Valid PDF file
        "test2.pdf",          # Case 2: Another valid PDF file
        "test3.txt",          # Case 3: Invalid file type (not a PDF)
        "non_existent.pdf",   # Case 4: File that does not exist
        "test4.pdf"           # Case 5: Valid PDF, where the 'uploads' directory already exists
    ]
    
    print("\n--- Running Test Cases ---")
    for i, test_file in enumerate(test_cases):
        print(f"\nTest Case {i + 1}: Processing '{test_file}'")
        success = save_pdf(test_file)
        print(f"Result: {'SUCCESS' if success else 'FAILURE'}")

if __name__ == "__main__":
    main()