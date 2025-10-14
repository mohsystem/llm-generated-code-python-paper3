import os
import base64

class Task50:
    UPLOAD_DIR = "uploads"

    class FileUploadServer:
        def __init__(self):
            # Create upload directory if it doesn't exist
            if not os.path.exists(Task50.UPLOAD_DIR):
                os.makedirs(Task50.UPLOAD_DIR)

        def handle_file_upload(self, file_name, file_data):
            try:
                # Save file to disk
                file_path = os.path.join(Task50.UPLOAD_DIR, file_name)
                with open(file_path, 'wb') as f:
                    f.write(file_data)

                return f"SUCCESS: File '{file_name}' uploaded successfully. Size: {len(file_data)} bytes"
            except Exception as e:
                return f"ERROR: Failed to upload file - {str(e)}"

        def file_exists(self, file_name):
            file_path = os.path.join(Task50.UPLOAD_DIR, file_name)
            return os.path.exists(file_path)

    class FileUploadClient:
        def upload_file(self, file_name, file_data, server):
            return server.handle_file_upload(file_name, file_data)


def main():
    print("File Upload System - Test Cases\n")

    server = Task50.FileUploadServer()
    client = Task50.FileUploadClient()

    # Test Case 1: Upload a text file
    print("Test Case 1: Upload text file")
    content1 = b"Hello, this is a test file!"
    result1 = client.upload_file("test1.txt", content1, server)
    print(result1)
    print(f"File exists: {server.file_exists('test1.txt')}")
    print()

    # Test Case 2: Upload a binary file
    print("Test Case 2: Upload binary file")
    binary_data = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    result2 = client.upload_file("test2.bin", binary_data, server)
    print(result2)
    print(f"File exists: {server.file_exists('test2.bin')}")
    print()

    # Test Case 3: Upload a larger file
    print("Test Case 3: Upload larger file")
    large_content = ""
    for i in range(1000):
        large_content += f"Line {i}: This is test data.\n"
    result3 = client.upload_file("test3.log", large_content.encode(), server)
    print(result3)
    print(f"File exists: {server.file_exists('test3.log')}")
    print()

    # Test Case 4: Upload file with special characters in name
    print("Test Case 4: Upload file with special characters")
    content4 = b"Special file content"
    result4 = client.upload_file("test_file-4.txt", content4, server)
    print(result4)
    print(f"File exists: {server.file_exists('test_file-4.txt')}")
    print()

    # Test Case 5: Upload empty file
    print("Test Case 5: Upload empty file")
    result5 = client.upload_file("empty.txt", b"", server)
    print(result5)
    print(f"File exists: {server.file_exists('empty.txt')}")
    print()


if __name__ == "__main__":
    main()
