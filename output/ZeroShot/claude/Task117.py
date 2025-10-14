
import zipfile
import tarfile
import gzip
import os
import shutil

def extract_zip(zip_file_path, dest_directory):
    """Extract ZIP file with path traversal protection"""
    os.makedirs(dest_directory, exist_ok=True)
    
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Security: Prevent path traversal attacks
            member_path = os.path.join(dest_directory, member)
            member_path = os.path.normpath(member_path)
            
            if not member_path.startswith(os.path.abspath(dest_directory)):
                raise Exception(f"Entry is outside of the target directory: {member}")
            
            zip_ref.extract(member, dest_directory)
    
    return f"Extracted {zip_file_path} to {dest_directory}"

def extract_tar(tar_file_path, dest_directory):
    """Extract TAR file with path traversal protection"""
    os.makedirs(dest_directory, exist_ok=True)
    
    with tarfile.open(tar_file_path, 'r') as tar_ref:
        for member in tar_ref.getmembers():
            # Security: Prevent path traversal attacks
            member_path = os.path.join(dest_directory, member.name)
            member_path = os.path.normpath(member_path)
            
            if not member_path.startswith(os.path.abspath(dest_directory)):
                raise Exception(f"Entry is outside of the target directory: {member.name}")
            
            tar_ref.extract(member, dest_directory)
    
    return f"Extracted {tar_file_path} to {dest_directory}"

def extract_tar_gz(tar_gz_file_path, dest_directory):
    """Extract TAR.GZ file with path traversal protection"""
    os.makedirs(dest_directory, exist_ok=True)
    
    with tarfile.open(tar_gz_file_path, 'r:gz') as tar_ref:
        for member in tar_ref.getmembers():
            # Security: Prevent path traversal attacks
            member_path = os.path.join(dest_directory, member.name)
            member_path = os.path.normpath(member_path)
            
            if not member_path.startswith(os.path.abspath(dest_directory)):
                raise Exception(f"Entry is outside of the target directory: {member.name}")
            
            tar_ref.extract(member, dest_directory)
    
    return f"Extracted {tar_gz_file_path} to {dest_directory}"

def create_test_zip(zip_path):
    """Helper function to create test ZIP file"""
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.writestr('test.txt', 'Hello, World!')

def create_test_zip_with_dirs(zip_path):
    """Helper function to create ZIP with directories"""
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.writestr('folder1/', '')
        zipf.writestr('folder1/file1.txt', 'File in folder')

def create_test_tar(tar_path):
    """Helper function to create test TAR file"""
    with tarfile.open(tar_path, 'w') as tar:
        info = tarfile.TarInfo(name='test.txt')
        content = b'Hello from TAR!'
        info.size = len(content)
        tar.addfile(info, fileobj=__import__('io').BytesIO(content))

def create_test_tar_gz(tar_gz_path):
    """Helper function to create test TAR.GZ file"""
    with tarfile.open(tar_gz_path, 'w:gz') as tar:
        info = tarfile.TarInfo(name='test.txt')
        content = b'Hello from TAR.GZ!'
        info.size = len(content)
        tar.addfile(info, fileobj=__import__('io').BytesIO(content))

def create_malicious_zip(zip_path):
    """Helper function to create malicious ZIP for testing"""
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.writestr('../../../etc/malicious.txt', 'Malicious content')

if __name__ == "__main__":
    try:
        # Test Case 1: Create and extract a simple ZIP file
        print("Test Case 1: Creating and extracting ZIP file")
        zip_path = "test1.zip"
        extract_dir1 = "extract1"
        create_test_zip(zip_path)
        result = extract_zip(zip_path, extract_dir1)
        print(result)
        
        # Test Case 2: Extract ZIP with nested directories
        print("\\nTest Case 2: ZIP with nested directories")
        zip_path2 = "test2.zip"
        extract_dir2 = "extract2"
        create_test_zip_with_dirs(zip_path2)
        result = extract_zip(zip_path2, extract_dir2)
        print(result)
        
        # Test Case 3: Create and extract TAR file
        print("\\nTest Case 3: Creating and extracting TAR file")
        tar_path = "test3.tar"
        extract_dir3 = "extract3"
        create_test_tar(tar_path)
        result = extract_tar(tar_path, extract_dir3)
        print(result)
        
        # Test Case 4: Extract TAR.GZ file
        print("\\nTest Case 4: Creating and extracting TAR.GZ file")
        tar_gz_path = "test4.tar.gz"
        extract_dir4 = "extract4"
        create_test_tar_gz(tar_gz_path)
        result = extract_tar_gz(tar_gz_path, extract_dir4)
        print(result)
        
        # Test Case 5: Test security - path traversal prevention
        print("\\nTest Case 5: Testing path traversal prevention")
        try:
            malicious_zip = "malicious.zip"
            extract_dir5 = "extract5"
            create_malicious_zip(malicious_zip)
            extract_zip(malicious_zip, extract_dir5)
            print("WARNING: Malicious file was extracted")
        except Exception as e:
            print(f"Security check passed: {e}")
        
    except Exception as e:
        print(f"Error: {e}")
