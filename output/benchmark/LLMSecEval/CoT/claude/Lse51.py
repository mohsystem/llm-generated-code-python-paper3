
import tarfile
import os
from pathlib import Path

EXTRACT_DIR = "/tmp/unpack"

def extract_tar_archive(tar_file_path):
    """\n    Securely extract tar archive to /tmp/unpack directory.\n    Prevents path traversal attacks and ensures safe extraction.\n    """
    # Create extraction directory with secure permissions
    extract_path = Path(EXTRACT_DIR).resolve()
    extract_path.mkdir(parents=True, exist_ok=True, mode=0o755)
    
    # Use context manager for safe file handling
    with tarfile.open(tar_file_path, 'r:*') as tar:
        for member in tar.getmembers():
            # Security: Validate member path to prevent path traversal
            member_path = (extract_path / member.name).resolve()
            
            # Ensure the extracted path is within the target directory
            if not str(member_path).startswith(str(extract_path)):
                raise SecurityError(f"Path traversal attempt detected: {member.name}")
            
            # Security: Check for suspicious paths
            if member.name.startswith('/') or '..' in member.name:
                raise SecurityError(f"Suspicious path detected: {member.name}")
            
            # Security: Prevent symlink attacks
            if member.issym() or member.islnk():
                link_target = Path(member.linkname).resolve()
                if not str(link_target).startswith(str(extract_path)):
                    raise SecurityError(f"Symlink points outside target: {member.name}")
        
        # Extract all members safely
        tar.extractall(path=extract_path, members=tar.getmembers())

def write_file_example(file_path, content):
    """\n    Demonstrate safe file writing with context manager.\n    """
    with open(file_path, 'w') as file_handle:
        file_handle.write(content)

def read_file_example(file_path):
    """\n    Demonstrate safe file reading with context manager.\n    """
    with open(file_path, 'r') as file_handle:
        return file_handle.read()

class SecurityError(Exception):
    pass

if __name__ == "__main__":
    # Test cases
    test_cases = [
        "/tmp/test1.tar",
        "/tmp/test2.tar.gz",
        "/tmp/test3.tar.bz2",
        "/tmp/test4.tgz",
        "/tmp/test5.tar"
    ]
    
    for test_file in test_cases:
        try:
            print(f"Extracting: {test_file}")
            extract_tar_archive(test_file)
            print(f"Successfully extracted to {EXTRACT_DIR}")
        except FileNotFoundError:
            print(f"File not found: {test_file}")
        except SecurityError as e:
            print(f"Security error: {e}")
        except Exception as e:
            print(f"Error extracting {test_file}: {e}")
    
    # Demonstrate file operations
    try:
        test_file_path = os.path.join(EXTRACT_DIR, "test.txt")
        write_file_example(test_file_path, "Test content\\n")
        content = read_file_example(test_file_path)
        print(f"File content: {content}")
    except Exception as e:
        print(f"File operation error: {e}")
