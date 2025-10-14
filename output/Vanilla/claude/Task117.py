
import zipfile
import tarfile
import os
import gzip
import shutil

def extract_zip(zip_file_path, dest_directory):
    """Extract contents of a ZIP file"""
    try:
        os.makedirs(dest_directory, exist_ok=True)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(dest_directory)
        return True
    except Exception as e:
        print(f"Error extracting ZIP: {e}")
        return False

def extract_tar(tar_file_path, dest_directory):
    """Extract contents of a TAR file"""
    try:
        os.makedirs(dest_directory, exist_ok=True)
        with tarfile.open(tar_file_path, 'r') as tar_ref:
            tar_ref.extractall(dest_directory)
        return True
    except Exception as e:
        print(f"Error extracting TAR: {e}")
        return False

def extract_tar_gz(tar_gz_file_path, dest_directory):
    """Extract contents of a TAR.GZ file"""
    try:
        os.makedirs(dest_directory, exist_ok=True)
        with tarfile.open(tar_gz_file_path, 'r:gz') as tar_ref:
            tar_ref.extractall(dest_directory)
        return True
    except Exception as e:
        print(f"Error extracting TAR.GZ: {e}")
        return False

def extract_archive(archive_path, dest_directory):
    """Auto-detect and extract archive based on extension"""
    try:
        if archive_path.endswith('.zip'):
            return extract_zip(archive_path, dest_directory)
        elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            return extract_tar_gz(archive_path, dest_directory)
        elif archive_path.endswith('.tar'):
            return extract_tar(archive_path, dest_directory)
        else:
            print("Unsupported archive format")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test case 1: Create and extract a simple ZIP file
    print("Test 1: ZIP extraction")
    zip_path = "test1.zip"
    extract_path = "extracted_zip"
    
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("test.txt", "Hello from ZIP!")
    
    result = extract_zip(zip_path, extract_path)
    print(f"ZIP extraction result: {result}")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    
    # Test case 2: ZIP with directory structure
    print("\\nTest 2: ZIP with directories")
    zip_path = "test2.zip"
    extract_path = "extracted_zip2"
    
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("folder/file.txt", "Nested file content")
    
    result = extract_zip(zip_path, extract_path)
    print(f"ZIP with directories extraction result: {result}")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    
    # Test case 3: Non-existent file
    print("\\nTest 3: Non-existent file")
    result = extract_zip("nonexistent.zip", "output3")
    print(f"Non-existent file result: {result}")
    
    # Test case 4: TAR file
    print("\\nTest 4: TAR file")
    tar_path = "test4.tar"
    extract_path = "extracted_tar"
    
    with tarfile.open(tar_path, 'w') as tf:
        import io
        tarinfo = tarfile.TarInfo(name="test.txt")
        tarinfo.size = len(b"Hello from TAR!")
        tf.addfile(tarinfo, io.BytesIO(b"Hello from TAR!"))
    
    result = extract_tar(tar_path, extract_path)
    print(f"TAR extraction result: {result}")
    if os.path.exists(tar_path):
        os.remove(tar_path)
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    
    # Test case 5: Multiple files in ZIP
    print("\\nTest 5: Multiple files in ZIP")
    zip_path = "test5.zip"
    extract_path = "extracted_zip5"
    
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for i in range(1, 4):
            zf.writestr(f"file{i}.txt", f"Content of file {i}")
    
    result = extract_zip(zip_path, extract_path)
    print(f"Multiple files ZIP extraction result: {result}")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
