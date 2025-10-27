
import os
from werkzeug.utils import secure_filename

class Lse72:
    def __init__(self):
        self.upload_folder = 'uploads'
        if not os.path.exists(self.upload_folder):
            os.makedirs(self.upload_folder)
    
    def upload_file(self, file, filename):
        """\n        Upload a file to the uploads folder\n        :param file: File object to upload\n        :param filename: Name of the file\n        :return: Path where file was saved\n        """
        try:
            # Secure the filename to prevent directory traversal attacks
            safe_filename = secure_filename(filename)
            filepath = os.path.join(self.upload_folder, safe_filename)
            
            # Save the file
            if hasattr(file, 'save'):
                file.save(filepath)
            else:
                # If file is a file-like object or bytes
                with open(filepath, 'wb') as f:
                    if isinstance(file, bytes):
                        f.write(file)
                    else:
                        f.write(file.read())
            
            return filepath
        except Exception as e:
            return f"Error uploading file: {str(e)}"

if __name__ == "__main__":
    uploader = Lse72()
    
    # Test Case 1: Upload directory creation
    print("Test Case 1: Upload directory created")
    print(f"Directory exists: {os.path.exists('uploads')}")
    
    # Test Case 2: Upload a text file
    print("\\nTest Case 2: Upload text file")
    test_content1 = b"This is test content 1"
    result = uploader.upload_file(test_content1, "test1.txt")
    print(f"File saved at: {result}")
    
    # Test Case 3: Upload another file
    print("\\nTest Case 3: Upload another file")
    test_content2 = b"This is test content 2"
    result = uploader.upload_file(test_content2, "test2.txt")
    print(f"File saved at: {result}")
    
    # Test Case 4: List uploaded files
    print("\\nTest Case 4: List uploaded files")
    files = os.listdir('uploads')
    print(f"Uploaded files: {files}")
    
    # Test Case 5: Verify file content
    print("\\nTest Case 5: Verify file content")
    try:
        with open(os.path.join('uploads', 'test1.txt'), 'rb') as f:
            content = f.read()
            print(f"Content of test1.txt: {content.decode()}")
    except Exception as e:
        print(f"Error reading file: {e}")
