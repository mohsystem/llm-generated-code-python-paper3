
import zipfile
import os

def extract_zip_archive(zip_file_path, dest_directory):
    os.makedirs(dest_directory, exist_ok=True)
    
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(dest_directory)

if __name__ == "__main__":
    # Test cases
    test_cases = [
        "archive.zip",
        "test1.zip",
        "test2.zip",
        "test3.zip",
        "test4.zip"
    ]
    
    for test_case in test_cases:
        try:
            print(f"Extracting: {test_case}")
            extract_zip_archive(test_case, "/tmp/unpack")
            print(f"Successfully extracted: {test_case}")
        except Exception as e:
            print(f"Error extracting {test_case}: {str(e)}")
