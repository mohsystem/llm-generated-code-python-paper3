
import zipfile
import os

def unzip_archive(zip_file_path, dest_directory):
    if not os.path.exists(dest_directory):
        os.makedirs(dest_directory)
    
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(dest_directory)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test case 1
    unzip_archive("archive.zip", "/tmp/unpack")
    
    # Test case 2
    unzip_archive("test1.zip", "/tmp/unpack1")
    
    # Test case 3
    unzip_archive("test2.zip", "/tmp/unpack2")
    
    # Test case 4
    unzip_archive("data.zip", "/tmp/unpack3")
    
    # Test case 5
    unzip_archive("files.zip", "/tmp/unpack4")
    
    print("Unzip operations completed.")
