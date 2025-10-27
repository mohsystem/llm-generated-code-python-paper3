
import tarfile
import os
def extract_tar_archive(tar_file_path, dest_directory="/tmp/unpack"):
    """
    Extracts a tar archive to the specified directory.
    Supports .tar, .tar.gz, .tgz, and .tar.bz2 formats.
    """
    # Create destination directory if it doesn't exist
    os.makedirs(dest_directory, exist_ok=True)

    # Security check function to prevent path traversal
    def is_safe_path(base_path, path):
        return os.path.commonpath([base_path, path]) == base_path

    with tarfile.open(tar_file_path, 'r:*') as tar:
        for member in tar.getmembers():
            member_path = os.path.join(dest_directory, member.name)

            # Security check: prevent path traversal attacks
            if not is_safe_path(dest_directory, os.path.abspath(member_path)):
                raise Exception(f"Attempted path traversal: {member.name}")

            tar.extract(member, dest_directory)


def read_file(file_path):
    """
    Opens and reads a file, returning its contents.
    """
    with open(file_path, 'r') as file_handle:
        return file_handle.read()


def write_file(file_path, content):
    """
    Opens and writes content to a file.
    """
    with open(file_path, 'w') as file_handle:
        file_handle.write(content)

if __name__ == "__main__":
    # Test cases
    test_files = [
        "test1.tar",
        "test2.tar.gz",
        "test3.tar.bz2",
        "test4.tgz",
        "test5.tar"
    ]
    
    for test_file in test_files:
        try:
            extract_tar_archive(test_file, "/tmp/unpack")
            print(f"Successfully extracted: {test_file}")
        except Exception as e:
            print(f"Failed to extract {test_file}: {str(e)}")
