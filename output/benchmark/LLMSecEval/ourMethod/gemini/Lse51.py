import tarfile
import os
import tempfile
import shutil
import sys
from pathlib import Path

def secure_extract_tar(tar_path, dest_dir):
    """
    Securely extracts a tar archive to a destination directory.
    It prevents path traversal attacks by ensuring all files are extracted inside the destination.
    
    :param tar_path: Path to the tar archive.
    :param dest_dir: Path to the destination directory.
    :return: True if extraction was successful, False otherwise.
    """
    try:
        # Get the real, absolute path of the destination directory
        real_dest_dir = os.path.realpath(dest_dir)
        
        # Ensure the destination is a directory
        if not os.path.isdir(real_dest_dir):
            if os.path.exists(real_dest_dir):
                 print(f"Error: Destination path '{real_dest_dir}' exists but is not a directory.", file=sys.stderr)
                 return False
            os.makedirs(real_dest_dir, mode=0o750)

        with tarfile.open(tar_path, "r:*") as tar:
            # It's recommended to iterate and extract manually for security
            for member in tar.getmembers():
                # Construct the full path for the member
                member_path = os.path.join(real_dest_dir, member.name)
                
                # Normalize the path to resolve '..' and other separators
                # This check is the core of the path traversal defense.
                # It ensures the resolved path is still inside the destination directory.
                real_member_path = os.path.realpath(member_path)

                if os.path.commonprefix([real_dest_dir, real_member_path]) != real_dest_dir:
                    print(f"Error: Attempted path traversal in tar file: '{member.name}'", file=sys.stderr)
                    return False

                if member.isdir():
                    # Create directory if it doesn't exist
                    os.makedirs(real_member_path, exist_ok=True, mode=0o750)
                elif member.isfile():
                    # Ensure parent directory exists before extracting file
                    parent_dir = os.path.dirname(real_member_path)
                    os.makedirs(parent_dir, exist_ok=True, mode=0o750)

                    # Extract file content safely
                    member_file_obj = tar.extractfile(member)
                    if member_file_obj:
                        with open(real_member_path, "wb") as dest_file:
                            shutil.copyfileobj(member_file_obj, dest_file)
                        os.chmod(real_member_path, 0o640) # Set restrictive permissions
                else:
                    # Ignore other types like symlinks, block devices, etc. for security
                    print(f"Skipping non-regular file/directory: {member.name}")

        return True
    except (tarfile.TarError, IOError, OSError) as e:
        print(f"An error occurred during tar extraction: {e}", file=sys.stderr)
        return False


def create_test_archives(base_dir):
    """Creates various tar files for testing purposes."""
    # Test 1: simple .tar.gz
    with tarfile.open(os.path.join(base_dir, "test1.tar.gz"), "w:gz") as tar:
        # Create a file in memory to add to the tar
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("content1")
            file_path = f.name
        tar.add(file_path, arcname="file1.txt")
        os.remove(file_path)

        # Create a directory structure
        os.makedirs(os.path.join(base_dir, "dir1"), exist_ok=True)
        with open(os.path.join(base_dir, "dir1/file2.txt"), "w") as f:
            f.write("content2")
        tar.add(os.path.join(base_dir, "dir1"), arcname="dir1")
    shutil.rmtree(os.path.join(base_dir, "dir1"))

    # Test 2: simple .tar.bz2
    with tarfile.open(os.path.join(base_dir, "test2.tar.bz2"), "w:bz2") as tar:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("content3")
            file_path = f.name
        tar.add(file_path, arcname="file3.txt")
        os.remove(file_path)

    # Test 3: path traversal
    with tarfile.open(os.path.join(base_dir, "test3_traversal.tar.gz"), "w:gz") as tar:
        info = tarfile.TarInfo(name="../../../pwned.txt")
        tar.addfile(info)

    # Test 4: absolute path
    with tarfile.open(os.path.join(base_dir, "test4_absolute.tar.gz"), "w:gz") as tar:
        info = tarfile.TarInfo(name="/tmp/absolute_pwned.txt")
        tar.addfile(info)
        
    # Test 5: symlink
    with tarfile.open(os.path.join(base_dir, "test5_symlink.tar.gz"), "w:gz") as tar:
        info = tarfile.TarInfo(name="link_to_file1")
        info.type = tarfile.SYMTYPE
        info.linkname = "file1.txt"
        tar.addfile(info)


def main():
    with tempfile.TemporaryDirectory() as test_archives_dir:
        print(f"Setting up test archives in: {test_archives_dir}")
        create_test_archives(test_archives_dir)

        # Test Case 1: Simple gzip tar
        with tempfile.TemporaryDirectory() as temp_dir1:
            print("\n--- Test Case 1: Simple .tar.gz ---")
            success1 = secure_extract_tar(os.path.join(test_archives_dir, "test1.tar.gz"), temp_dir1)
            print(f"Extraction success: {success1}")
            print(f"Check file1.txt exists: {os.path.exists(os.path.join(temp_dir1, 'file1.txt'))}")
            print(f"Check dir1/file2.txt exists: {os.path.exists(os.path.join(temp_dir1, 'dir1/file2.txt'))}")

        # Test Case 2: Simple bzip2 tar
        with tempfile.TemporaryDirectory() as temp_dir2:
            print("\n--- Test Case 2: Simple .tar.bz2 ---")
            success2 = secure_extract_tar(os.path.join(test_archives_dir, "test2.tar.bz2"), temp_dir2)
            print(f"Extraction success: {success2}")
            print(f"Check file3.txt exists: {os.path.exists(os.path.join(temp_dir2, 'file3.txt'))}")

        # Test Case 3: Path Traversal
        with tempfile.TemporaryDirectory() as temp_dir3:
            print("\n--- Test Case 3: Path Traversal (should fail) ---")
            success3 = secure_extract_tar(os.path.join(test_archives_dir, "test3_traversal.tar.gz"), temp_dir3)
            print(f"Extraction success: {success3}")
            pwned_file = Path(temp_dir3).joinpath("../pwned.txt").resolve()
            print(f"Check for traversal file {pwned_file} exists: {os.path.exists(pwned_file)}")

        # Test Case 4: Absolute Path
        with tempfile.TemporaryDirectory() as temp_dir4:
            print("\n--- Test Case 4: Absolute Path (should fail) ---")
            success4 = secure_extract_tar(os.path.join(test_archives_dir, "test4_absolute.tar.gz"), temp_dir4)
            print(f"Extraction success: {success4}")
            abs_pwned_file = "/tmp/absolute_pwned.txt"
            print(f"Check for absolute file {abs_pwned_file} exists: {os.path.exists(abs_pwned_file)}")
            if os.path.exists(abs_pwned_file):
                os.remove(abs_pwned_file)

        # Test Case 5: Symlink
        with tempfile.TemporaryDirectory() as temp_dir5:
            print("\n--- Test Case 5: Symlink (should be skipped) ---")
            success5 = secure_extract_tar(os.path.join(test_archives_dir, "test5_symlink.tar.gz"), temp_dir5)
            print(f"Extraction success: {success5}")
            print(f"Check symlink exists: {os.path.lexists(os.path.join(temp_dir5, 'link_to_file1'))}")

    print("\nCleanup complete.")


if __name__ == "__main__":
    main()