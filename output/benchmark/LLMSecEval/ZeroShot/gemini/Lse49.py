import os
import zipfile
import shutil
import stat

# The prompt asks to open the archive.zip file as a tarfile, which is contradictory.
# .zip files are handled by the zipfile module, while .tar files are handled by the tarfile module.
# Based on the filename "archive.zip", this code will correctly handle a ZIP archive.

def unzip_archive(zip_file_path: str, dest_dir: str):
    """
    Unzips a zip file to a specified destination directory, 
    preventing path traversal (Zip Slip) attacks.
    """
    # Ensure destination directory exists
    os.makedirs(dest_dir, exist_ok=True)
    
    # Get the absolute path of the destination directory for security checks
    abs_dest_dir = os.path.abspath(dest_dir)

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # Construct the full path for the member
            target_path = os.path.join(abs_dest_dir, member.filename)
            
            # Security Check: Resolve the absolute path of the target
            abs_target_path = os.path.abspath(target_path)

            # Check if the resolved path is within the destination directory
            if not abs_target_path.startswith(abs_dest_dir):
                print(f"Skipping malicious path: {member.filename}")
                continue
            
            # It's safe to extract this member
            zip_ref.extract(member, dest_dir)

def create_test_zip(zip_file_name: str, test_case: int):
    """Helper to create a test zip file."""
    with zipfile.ZipFile(zip_file_name, 'w') as zf:
        zf.writestr("file1.txt", "content of file1")
        zf.writestr("dir1/file2.txt", "content of file2")
        
        # Add a malicious entry for some tests
        if test_case > 1:
            zf.writestr("../../evil.txt", "malicious content")

def on_rm_error(func, path, exc_info):
    """
    Error handler for shutil.rmtree.
    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

def cleanup(zip_file_name: str, unpack_dir: str):
    """Helper to clean up test files and directories."""
    if os.path.exists(zip_file_name):
        os.remove(zip_file_name)
    if os.path.isdir(unpack_dir):
        shutil.rmtree(unpack_dir, onerror=on_rm_error)
    # Clean up potential traversal file
    evil_file = os.path.abspath(os.path.join('/tmp', 'evil.txt'))
    if os.path.exists(evil_file):
        os.remove(evil_file)
        
def main():
    """Main function with test cases."""
    zip_file_name = "archive.zip"
    unpack_dir = "/tmp/unpack"
    
    for i in range(1, 6):
        print(f"--- Running Test Case {i} ---")
        try:
            # Setup
            create_test_zip(zip_file_name, i)
            print(f"Created {zip_file_name}")

            # Execute
            unzip_archive(zip_file_name, unpack_dir)
            print(f"Successfully ran unzip on {unpack_dir}")
            
            # Verify
            p1 = os.path.join(unpack_dir, "file1.txt")
            p2 = os.path.join(unpack_dir, "dir1", "file2.txt")
            p3 = os.path.abspath("/tmp/evil.txt")
            
            if os.path.exists(p1):
                print(f"Verified: {p1} exists.")
            if os.path.exists(p2):
                print(f"Verified: {p2} exists.")
            if os.path.exists(p3):
                print(f"SECURITY VULNERABILITY: Traversal file created at {p3}", flush=True)
            else:
                print("Security check passed: Traversal file was not created.")

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            # Teardown
            print("Cleaning up...")
            cleanup(zip_file_name, unpack_dir)
            print("---------------------------\n")

if __name__ == "__main__":
    main()