import os
import tarfile
import pathlib
import shutil

def extract_tar_safely(tar_path: str, dest_dir: str):
    """
    Safely extracts a tar archive to a destination directory,
    preventing path traversal (Zip Slip) attacks.
    """
    if not os.path.exists(tar_path):
        print(f"Error: Archive file not found: {tar_path}")
        return False
        
    # Create destination directory if it doesn't exist
    pathlib.Path(dest_dir).mkdir(parents=True, exist_ok=True)
    
    # Get the real, absolute path of the destination directory
    # to prevent shenanigans with symlinks or '..'
    real_dest_path = os.path.realpath(dest_dir)
    
    print(f"Extracting {tar_path} to {real_dest_path}")
    
    try:
        with tarfile.open(tar_path, "r:*") as tf:
            for member in tf.getmembers():
                # Construct the full target path
                target_path = os.path.join(real_dest_path, member.name)
                
                # Get the real, absolute path of the target
                real_target_path = os.path.realpath(target_path)
                
                # Security Check: Ensure the extracted file is within the destination directory
                if not real_target_path.startswith(real_dest_path):
                    print(f"SECURITY: Skipping potentially malicious entry: {member.name}")
                    continue
                
                # Security Check: Skip absolute paths
                if os.path.isabs(member.name):
                    print(f"SECURITY: Skipping absolute path entry: {member.name}")
                    continue

                print(f"  -> {member.name}")
                # Use extract() on a single member, which is generally safer than extractall
                tf.extract(member, path=real_dest_path)
        return True
    except tarfile.TarError as e:
        print(f"Error reading tar file {tar_path}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def create_test_archives(base_dir: str):
    """Creates a set of tar archives for testing purposes."""
    source_dir = os.path.join(base_dir, "source_files")
    archive_dir = base_dir

    # Clean up previous runs
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)

    # Create source files
    os.makedirs(os.path.join(source_dir, "subdir"))
    with open(os.path.join(source_dir, "file1.txt"), "w") as f:
        f.write("This is file 1.\n")
    with open(os.path.join(source_dir, "subdir", "file2.txt"), "w") as f:
        f.write("This is file 2 in a subdirectory.\n")

    print(f"Creating test archives in {archive_dir}")

    # 1. Simple .tar
    with tarfile.open(os.path.join(archive_dir, "test.tar"), "w") as tar:
        tar.add(source_dir, arcname=".")
    
    # 2. Gzip compressed .tar.gz
    with tarfile.open(os.path.join(archive_dir, "test.tar.gz"), "w:gz") as tar:
        tar.add(source_dir, arcname=".")

    # 3. Bzip2 compressed .tar.bz2
    with tarfile.open(os.path.join(archive_dir, "test.tar.bz2"), "w:bz2") as tar:
        tar.add(source_dir, arcname=".")
        
    # 4. Malicious path traversal
    with tarfile.open(os.path.join(archive_dir, "malicious_traversal.tar"), "w") as tar:
        # Add a normal file
        tar.add(os.path.join(source_dir, "file1.txt"), arcname="good_file.txt")
        # Add a malicious file
        malicious_info = tarfile.TarInfo(name="../../evil.txt")
        tar.addfile(malicious_info)

    # 5. Malicious absolute path
    with tarfile.open(os.path.join(archive_dir, "malicious_absolute.tar"), "w") as tar:
        # Add a normal file
        tar.add(os.path.join(source_dir, "file1.txt"), arcname="another_good_file.txt")
        # Add a malicious file
        abs_path = os.path.abspath(os.path.join(os.path.sep, 'tmp', 'evil_absolute.txt'))
        malicious_info_abs = tarfile.TarInfo(name=abs_path)
        tar.addfile(malicious_info_abs)
        
    print("Test archive creation complete.")

def main():
    """Main function to run test cases."""
    test_data_base_dir = "/tmp/lse51_test_data"
    unpack_dir = "/tmp/unpack_python"
    
    # Create archives for all language tests to use
    create_test_archives(test_data_base_dir)
    
    test_archives = [
        os.path.join(test_data_base_dir, "test.tar"),
        os.path.join(test_data_base_dir, "test.tar.gz"),
        os.path.join(test_data_base_dir, "test.tar.bz2"),
        os.path.join(test_data_base_dir, "malicious_traversal.tar"),
        os.path.join(test_data_base_dir, "malicious_absolute.tar")
    ]
    
    print("\n--- Python Tar Extraction Tests ---")
    for i, archive_path in enumerate(test_archives):
        print(f"\n--- Test Case {i + 1} ---")
        if os.path.exists(unpack_dir):
            shutil.rmtree(unpack_dir)
        extract_tar_safely(archive_path, unpack_dir)
        
    # Optional: Clean up all created files and directories
    # shutil.rmtree(test_data_base_dir)
    # if os.path.exists(unpack_dir):
    #     shutil.rmtree(unpack_dir)
    print("\n--- Python Tests Complete ---")
    print(f"NOTE: Test archives for other languages are now available in {test_data_base_dir}")

if __name__ == "__main__":
    main()