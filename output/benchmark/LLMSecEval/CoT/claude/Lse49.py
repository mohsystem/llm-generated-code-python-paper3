
import zipfile
import os
import sys
def unzip_archive(zip_file_path, dest_directory):
    """Safely extract zip file to destination directory"""
    # Create destination directory if it doesn't exist
    os.makedirs(dest_directory, exist_ok=True)

    # Get canonical path to prevent path traversal
    dest_path = os.path.abspath(dest_directory)

    try:
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            for member in zip_ref.namelist():
                # Security check: prevent path traversal
                member_path = os.path.abspath(os.path.join(dest_directory, member))
                if not member_path.startswith(dest_path + os.sep) and member_path != dest_path:
                    raise Exception(f"Attempted path traversal in zip file: {member}")

                # Extract the file safely
                zip_ref.extract(member, dest_directory)

        return True
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

def main():
    test_cases = [
        "archive.zip",
        "test1.zip",
        "test2.zip",
        "test3.zip",
        "test4.zip"
    ]
    
    for test_case in test_cases:
        print(f"Extracting: {test_case}")
        if unzip_archive(test_case, "/tmp/unpack"):
            print(f"Successfully extracted: {test_case}")
        else:
            print(f"Failed to extract: {test_case}")

if __name__ == "__main__":
    main()
