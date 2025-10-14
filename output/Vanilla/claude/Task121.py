
import os
import shutil

UPLOAD_DIRECTORY = "uploads"

def upload_file(source_file_path, destination_file_name):
    try:
        # Create upload directory if it doesn't exist
        if not os.path.exists(UPLOAD_DIRECTORY):
            os.makedirs(UPLOAD_DIRECTORY)

        # Check if source file exists
        if not os.path.exists(source_file_path):
            print(f"Source file does not exist: {source_file_path}")
            return False

        # Copy file to upload directory
        destination_path = os.path.join(UPLOAD_DIRECTORY, destination_file_name)
        shutil.copy2(source_file_path, destination_path)
        print(f"File uploaded successfully: {destination_file_name}")
        return True

    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        return False

def upload_file_with_content(file_name, content):
    try:
        # Create upload directory if it doesn't exist
        if not os.path.exists(UPLOAD_DIRECTORY):
            os.makedirs(UPLOAD_DIRECTORY)

        # Write content to file
        destination_path = os.path.join(UPLOAD_DIRECTORY, file_name)
        with open(destination_path, 'w') as f:
            f.write(content)

        print(f"File uploaded successfully: {file_name}")
        return True
    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        return False

def list_uploaded_files():
    files = []
    
    if os.path.exists(UPLOAD_DIRECTORY) and os.path.isdir(UPLOAD_DIRECTORY):
        files = [f for f in os.listdir(UPLOAD_DIRECTORY) 
                if os.path.isfile(os.path.join(UPLOAD_DIRECTORY, f))]
    
    return files

if __name__ == "__main__":
    print("=== File Upload Program ===\\n")
    
    # Test Case 1: Upload a file with content
    print("Test Case 1: Upload text file")
    result1 = upload_file_with_content("test1.txt", "Hello, this is test file 1!")
    print(f"Result: {result1}\\n")
    
    # Test Case 2: Upload another file with content
    print("Test Case 2: Upload document")
    result2 = upload_file_with_content("document.txt", "This is a sample document with multiple lines.\\nLine 2\\nLine 3")
    print(f"Result: {result2}\\n")
    
    # Test Case 3: Upload a file with JSON content
    print("Test Case 3: Upload JSON file")
    result3 = upload_file_with_content("data.json", "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}")
    print(f"Result: {result3}\\n")
    
    # Test Case 4: Upload a file with special characters
    print("Test Case 4: Upload file with special characters")
    result4 = upload_file_with_content("special.txt", "Special chars: !@#$%^&*()")
    print(f"Result: {result4}\\n")
    
    # Test Case 5: List all uploaded files
    print("Test Case 5: List all uploaded files")
    uploaded_files = list_uploaded_files()
    print("Uploaded files:")
    for file in uploaded_files:
        print(f"  - {file}")
