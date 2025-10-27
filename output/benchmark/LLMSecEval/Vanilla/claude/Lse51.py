
import tarfile
import os

def unzip_tar_archive(tar_file_path, dest_directory="/tmp/unpack"):
    """\n    Unzip tar archives to destination directory including gzip and bz2 compression\n    """
    os.makedirs(dest_directory, exist_ok=True)
    
    with tarfile.open(tar_file_path, 'r:*') as tar:
        tar.extractall(path=dest_directory)
    
    return dest_directory

def open_file(file_path, mode='r'):
    """\n    Open and return a file handle\n    """
    with open(file_path, mode) as file_handle:
        return file_handle.read() if 'r' in mode else None

if __name__ == "__main__":
    # Test cases
    test_cases = [
        "test1.tar.gz",
        "test2.tar.bz2",
        "test3.tar",
        "test4.tgz",
        "test5.tar.gz"
    ]
    
    for test_case in test_cases:
        try:
            print(f"Extracting: {test_case}")
            result = unzip_tar_archive(test_case, "/tmp/unpack")
            print(f"Successfully extracted {test_case} to {result}")
        except FileNotFoundError:
            print(f"File not found: {test_case}")
        except Exception as e:
            print(f"Error extracting {test_case}: {str(e)}")
