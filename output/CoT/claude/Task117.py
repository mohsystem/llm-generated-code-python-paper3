
import os
import zipfile
import tarfile
import shutil
from pathlib import Path

class Task117:
    
    @staticmethod
    def is_valid_path(dest_dir, file_path):
        """Validate path to prevent path traversal attacks"""
        dest_dir_resolved = Path(dest_dir).resolve()
        target_path = (dest_dir_resolved / file_path).resolve()
        return str(target_path).startswith(str(dest_dir_resolved) + os.sep)
    
    @staticmethod
    def extract_zip(zip_file_path, dest_dir):
        """Extract ZIP files with security validation"""
        os.makedirs(dest_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                # Validate path to prevent path traversal
                if not Task117.is_valid_path(dest_dir, member):
                    raise ValueError(f"Invalid entry path detected: {member}")
                
                # Extract safely
                zip_ref.extract(member, dest_dir)
        
        print(f"ZIP extraction completed: {zip_file_path}")
        return True
    
    @staticmethod
    def extract_tar(tar_file_path, dest_dir):
        """Extract TAR files (including .tar.gz) with security validation"""
        os.makedirs(dest_dir, exist_ok=True)
        
        # Determine compression mode
        if tar_file_path.endswith('.tar.gz') or tar_file_path.endswith('.tgz'):
            mode = 'r:gz'
        elif tar_file_path.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            mode = 'r'
        
        with tarfile.open(tar_file_path, mode) as tar_ref:
            for member in tar_ref.getmembers():
                # Validate path to prevent path traversal
                if not Task117.is_valid_path(dest_dir, member.name):
                    raise ValueError(f"Invalid entry path detected: {member.name}")
                
                # Additional security checks
                if member.name.startswith('/') or '..' in member.name:
                    raise ValueError(f"Unsafe path detected: {member.name}")
                
                tar_ref.extract(member, dest_dir)
        
        print(f"TAR extraction completed: {tar_file_path}")
        return True
    
    @staticmethod
    def extract_archive(archive_path, dest_dir):
        """Auto-detect and extract archive based on extension"""
        archive_path = archive_path.lower()
        
        if archive_path.endswith('.zip'):
            return Task117.extract_zip(archive_path, dest_dir)
        elif archive_path.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2')):
            return Task117.extract_tar(archive_path, dest_dir)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")


def create_test_zip(zip_path, content="Test content"):
    """Helper function to create test ZIP file"""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr('test.txt', content)


def create_test_zip_with_subdirs(zip_path):
    """Helper function to create ZIP with subdirectories"""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr('subdir/', '')
        zf.writestr('subdir/file.txt', 'Subdirectory content')


def create_test_tar(tar_path):
    """Helper function to create test TAR file"""
    with tarfile.open(tar_path, 'w') as tf:
        import io
        content = b'TAR test content'
        tarinfo = tarfile.TarInfo(name='test.txt')
        tarinfo.size = len(content)
        tf.addfile(tarinfo, io.BytesIO(content))


def create_malicious_zip(zip_path):
    """Helper function to create malicious ZIP with path traversal"""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr('../../etc/passwd', 'malicious content')


def create_empty_zip(zip_path):
    """Helper function to create empty ZIP"""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        pass


def main():
    print("Archive Extraction Program - Test Cases\\n")
    
    # Test Case 1: Extract a simple ZIP file
    try:
        test_zip1 = "test1.zip"
        create_test_zip(test_zip1)
        Task117.extract_zip(test_zip1, "extracted_zip1")
        print("Test 1 passed: Simple ZIP extraction\\n")
        os.remove(test_zip1)
        shutil.rmtree("extracted_zip1", ignore_errors=True)
    except Exception as e:
        print(f"Test 1 error: {e}\\n")
    
    # Test Case 2: Extract ZIP with subdirectories
    try:
        test_zip2 = "test2.zip"
        create_test_zip_with_subdirs(test_zip2)
        Task117.extract_zip(test_zip2, "extracted_zip2")
        print("Test 2 passed: ZIP with subdirectories\\n")
        os.remove(test_zip2)
        shutil.rmtree("extracted_zip2", ignore_errors=True)
    except Exception as e:
        print(f"Test 2 error: {e}\\n")
    
    # Test Case 3: Extract TAR file
    try:
        test_tar = "test.tar"
        create_test_tar(test_tar)
        Task117.extract_tar(test_tar, "extracted_tar")
        print("Test 3 passed: TAR extraction\\n")
        os.remove(test_tar)
        shutil.rmtree("extracted_tar", ignore_errors=True)
    except Exception as e:
        print(f"Test 3 error: {e}\\n")
    
    # Test Case 4: Test path traversal prevention
    try:
        malicious_zip = "malicious.zip"
        create_malicious_zip(malicious_zip)
        Task117.extract_zip(malicious_zip, "safe_output")
        print("Test 4 failed: Should have prevented path traversal\\n")
        os.remove(malicious_zip)
    except ValueError:
        print("Test 4 passed: Path traversal prevented\\n")
        os.remove("malicious.zip")
    except Exception as e:
        print(f"Test 4 error: {e}\\n")
    
    # Test Case 5: Empty archive handling
    try:
        empty_zip = "empty.zip"
        create_empty_zip(empty_zip)
        Task117.extract_zip(empty_zip, "extracted_empty")
        print("Test 5 passed: Empty ZIP handled\\n")
        os.remove(empty_zip)
        shutil.rmtree("extracted_empty", ignore_errors=True)
    except Exception as e:
        print(f"Test 5 error: {e}\\n")


if __name__ == "__main__":
    main()
