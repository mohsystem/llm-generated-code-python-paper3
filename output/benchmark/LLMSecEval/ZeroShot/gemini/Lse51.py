import tarfile
import os
import shutil
import io

TEST_DIR = "/tmp/unpack_python_test"

def secure_untar(tar_path, extract_path):
    """
    Securely extracts a tar archive to a specified directory.
    Prevents path traversal attacks by ensuring that all extracted files are within the destination directory.
    
    Args:
        tar_path (str): The path to the .tar file.
        extract_path (str): The destination directory for extraction.
    
    Returns:
        bool: True if extraction was successful, False otherwise.
    """
    try:
        # The 'with' statement ensures the tar file is properly closed.
        with tarfile.open(tar_path, "r:*") as tar:
            # Get the absolute path of the destination directory
            dest_path_abs = os.path.abspath(extract_path)

            for member in tar.getmembers():
                member_path_abs = os.path.abspath(os.path.join(extract_path, member.name))

                # Security check: ensure the member's path is within the destination directory
                if not member_path_abs.startswith(dest_path_abs):
                    print(f"Security Error: Malicious member detected (Path Traversal): {member.name}")
                    return False

                # It's safe to extract this member
                tar.extract(member, path=extract_path)
        return True
    except tarfile.TarError as e:
        print(f"Error: Invalid or corrupted TAR file at {tar_path}: {e}")
        return False
    except FileNotFoundError:
        print(f"Error: TAR file not found at {tar_path}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

# --- Test Case Setup ---

def setup_test_environment():
    """Creates test files and directories."""
    cleanup_test_environment()  # Clean up from previous runs
    os.makedirs(TEST_DIR, exist_ok=True)

    # 1. Create a valid tar file
    with tarfile.open("good.tar", "w") as tar:
        # Add a file
        file1_data = b"This is file 1."
        tarinfo1 = tarfile.TarInfo(name="file1.txt")
        tarinfo1.size = len(file1_data)
        tar.addfile(tarinfo1, io.BytesIO(file1_data))
        # Add a file in a directory
        file2_data = b"This is file 2 in a directory."
        tarinfo2 = tarfile.TarInfo(name="dir1/file2.txt")
        tarinfo2.size = len(file2_data)
        tar.addfile(tarinfo2, io.BytesIO(file2_data))

    # 2. Create a tar file with a path traversal attempt
    with tarfile.open("bad_traversal.tar", "w") as tar:
        data = b"malicious content"
        tarinfo = tarfile.TarInfo(name="../../tmp/evil.txt")
        tarinfo.size = len(data)
        tar.addfile(tarinfo, io.BytesIO(data))

    # 3. Create a tar file with an absolute path attempt
    with tarfile.open("bad_absolute.tar", "w") as tar:
        data = b"malicious absolute content"
        tarinfo = tarfile.TarInfo(name="/tmp/evil_absolute.txt")
        tarinfo.size = len(data)
        tar.addfile(tarinfo, io.BytesIO(data))

    # 5. Create an empty/corrupt tar file (just create an empty file)
    with open("corrupt.tar", "w") as f:
        f.write("this is not a tar file")


def cleanup_test_environment():
    """Removes test files and directories."""
    if os.path.isdir(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    for f in ["good.tar", "bad_traversal.tar", "bad_absolute.tar", "corrupt.tar"]:
        if os.path.exists(f):
            os.remove(f)

def main():
    """Runs test cases."""
    setup_test_environment()
    print("--- Running Python Test Cases ---")

    # Test Case 1: Valid tar file
    print("\n[Test 1] Extracting a valid TAR file...")
    result1 = secure_untar("good.tar", TEST_DIR)
    print(f"Result: {'SUCCESS' if result1 else 'FAILURE'}")
    assert result1
    assert os.path.exists(os.path.join(TEST_DIR, "file1.txt"))

    # Test Case 2: Path traversal attack
    print("\n[Test 2] Extracting a TAR with path traversal...")
    result2 = secure_untar("bad_traversal.tar", TEST_DIR)
    print(f"Result: {'SUCCESS (Attack Blocked)' if not result2 else 'FAILURE (Vulnerable)'}")
    assert not result2
    assert not os.path.exists("/tmp/evil.txt")

    # Test Case 3: Absolute path attack
    print("\n[Test 3] Extracting a TAR with an absolute path...")
    result3 = secure_untar("bad_absolute.tar", TEST_DIR)
    print(f"Result: {'SUCCESS (Attack Blocked)' if not result3 else 'FAILURE (Vulnerable)'}")
    assert not result3
    assert not os.path.exists("/tmp/evil_absolute.txt")

    # Test Case 4: Non-existent file
    print("\n[Test 4] Attempting to extract a non-existent TAR file...")
    result4 = secure_untar("non_existent.tar", TEST_DIR)
    print(f"Result: {'SUCCESS (Handled gracefully)' if not result4 else 'FAILURE'}")
    assert not result4

    # Test Case 5: Corrupt tar file
    print("\n[Test 5] Extracting a corrupt TAR file...")
    result5 = secure_untar("corrupt.tar", TEST_DIR)
    print(f"Result: {'SUCCESS (Handled gracefully)' if not result5 else 'FAILURE'}")
    assert not result5

    cleanup_test_environment()
    print("\n--- Python Tests Complete, Cleanup Done ---")

if __name__ == "__main__":
    main()