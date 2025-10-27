import tarfile
import os
import shutil

def extract_archive(archive_path, dest_dir):
    """
    Extracts a tar archive (including gzipped or bz2 compressed) to a destination directory.
    The with statement ensures the tarfile is properly closed.
    """
    if not os.path.exists(archive_path):
        print(f"Error: Archive not found at '{archive_path}'")
        return False
    try:
        # The 'r:*' mode automatically detects the compression (gz, bz2, or none)
        with tarfile.open(archive_path, 'r:*') as tar:
            # The open() function returns a file-like object for the archive
            print(f"Extracting '{archive_path}' to '{dest_dir}'...")
            tar.extractall(path=dest_dir)
        print("Extraction successful.")
        return True
    except tarfile.TarError as e:
        print(f"Error extracting archive: {e}")
        return False
    except FileNotFoundError:
        print(f"Error: Could not create destination directory '{dest_dir}'")
        return False

def create_test_environment():
    """Sets up directories and archives for all language test cases."""
    print("--- Setting up test environment in /tmp ---")
    
    # Cleanup previous runs
    paths_to_clean = [
        '/tmp/source_simple', '/tmp/source_nested', '/tmp/simple.tar.gz', '/tmp/simple.tar.bz2',
        '/tmp/nested.tar.gz', '/tmp/empty.tar.gz', '/tmp/py_unpack_1', '/tmp/py_unpack_2',
        '/tmp/py_unpack_3', '/tmp/py_unpack_4', '/tmp/py_unpack_5', '/tmp/cpp_unpack_1', '/tmp/cpp_unpack_2',
        '/tmp/cpp_unpack_3', '/tmp/cpp_unpack_4', '/tmp/cpp_unpack_5', '/tmp/c_unpack_1', '/tmp/c_unpack_2',
        '/tmp/c_unpack_3', '/tmp/c_unpack_4', '/tmp/c_unpack_5', '/tmp/java_unpack_1', '/tmp/java_unpack_2',
        '/tmp/java_unpack_3', '/tmp/java_new_dir', '/tmp/java_unpack_5'
    ]
    for path in paths_to_clean:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.isfile(path):
            os.remove(path)

    # Create source files for simple archive
    os.makedirs('/tmp/source_simple', exist_ok=True)
    with open('/tmp/source_simple/file1.txt', 'w') as f:
        f.write('This is file 1.\n')
    with open('/tmp/source_simple/file2.log', 'w') as f:
        f.write('This is a log file.\n')

    # Create source files for nested archive
    os.makedirs('/tmp/source_nested/subdir', exist_ok=True)
    with open('/tmp/source_nested/root.txt', 'w') as f:
        f.write('File in root.\n')
    with open('/tmp/source_nested/subdir/nested.txt', 'w') as f:
        f.write('File in subdir.\n')

    # Create archives
    with tarfile.open('/tmp/simple.tar.gz', 'w:gz') as tar:
        tar.add('/tmp/source_simple', arcname='.')
    with tarfile.open('/tmp/simple.tar.bz2', 'w:bz2') as tar:
        tar.add('/tmp/source_simple', arcname='.')
    with tarfile.open('/tmp/nested.tar.gz', 'w:gz') as tar:
        tar.add('/tmp/source_nested', arcname='.')
    with tarfile.open('/tmp/empty.tar.gz', 'w:gz') as tar:
        pass # Create an empty archive

    print("Test environment created successfully.")


if __name__ == "__main__":
    create_test_environment()
    
    print("\n--- Running Python Tests ---")

    # Test Case 1: Extract a standard tar.gz archive
    print("\n[Test 1] Extracting simple.tar.gz")
    extract_archive("/tmp/simple.tar.gz", "/tmp/py_unpack_1")

    # Test Case 2: Extract a tar.bz2 archive
    print("\n[Test 2] Extracting simple.tar.bz2")
    extract_archive("/tmp/simple.tar.bz2", "/tmp/py_unpack_2")

    # Test Case 3: Attempt to extract a non-existent file
    print("\n[Test 3] Extracting non_existent.tar.gz (expecting error)")
    extract_archive("/tmp/non_existent.tar.gz", "/tmp/py_unpack_3")

    # Test Case 4: Extract an archive with subdirectories
    print("\n[Test 4] Extracting nested.tar.gz")
    extract_archive("/tmp/nested.tar.gz", "/tmp/py_unpack_4")

    # Test Case 5: Extract to a destination that doesn't exist (should be created)
    print("\n[Test 5] Extracting to a new directory /tmp/py_unpack_5")
    extract_archive("/tmp/simple.tar.gz", "/tmp/py_unpack_5")

    print("\nPython tests finished. Test files are in /tmp for other languages to use.")
    # You can manually clean up with:
    # shutil.rmtree('/tmp/source_simple'); os.remove('/tmp/simple.tar.gz'); ... etc.