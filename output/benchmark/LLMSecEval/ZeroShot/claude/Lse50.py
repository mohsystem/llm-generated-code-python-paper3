
import zipfile
import os
import tarfile

import os
import zipfile
import tarfile

def extract_archive(archive_path, dest_directory):
    """
    Extracts archive.zip or archive.tar(.gz/.bz2) files to the specified directory.
    Prevents path traversal attacks by validating extraction paths.

    Args:
        archive_path (str): Path to the archive file (.zip or .tar[.gz|.bz2]).
        dest_directory (str): Directory where the archive should be extracted.

    Returns:
        bool: True if extraction is successful, False otherwise.
    """
    os.makedirs(dest_directory, exist_ok=True)
    dest_directory = os.path.abspath(dest_directory)

    try:
        # Attempt to extract as ZIP archive
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                member_path = os.path.abspath(os.path.join(dest_directory, member))
                if not member_path.startswith(dest_directory):
                    raise Exception(f"Path traversal detected: {member}")
            zip_ref.extractall(dest_directory)
            return True

    except zipfile.BadZipFile:
        # If not a ZIP, attempt to extract as TAR archive
        try:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                for member in tar_ref.getmembers():
                    member_path = os.path.abspath(os.path.join(dest_directory, member.name))
                    if not member_path.startswith(dest_directory):
                        raise Exception(f"Path traversal detected: {member.name}")
                tar_ref.extractall(dest_directory, filter='data')  # filter='data' prevents special file types
                return True

        except Exception as e:
            print(f"Error extracting tar file: {e}")
            return False

    except Exception as e:
        print(f"Error extracting file: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    test_cases = [
        "archive.zip",
        "test1.zip",
        "test2.tar",
        "test3.tar.gz",
        "test4.zip"
    ]
    
    for test_case in test_cases:
        print(f"Attempting to extract: {test_case}")
        result = extract_archive(test_case, "/tmp/unpack")
        if result:
            print(f"Successfully extracted: {test_case}")
        else:
            print(f"Failed to extract: {test_case}")
        print("-" * 50)
