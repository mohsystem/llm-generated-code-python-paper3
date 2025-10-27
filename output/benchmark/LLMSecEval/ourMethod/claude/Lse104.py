
import os
import tempfile
import sys

def write_config_file(filename, content):
    """\n    Securely write content to a file with proper validation and permissions.\n    Returns True on success, False on failure.\n    """
    if filename is None or content is None:
        return False
    
    # Get base directory and normalize paths to prevent directory traversal
    base_dir = os.path.abspath(os.getcwd())
    file_path = os.path.abspath(os.path.join(base_dir, filename))
    
    # Ensure resolved path is within base directory
    if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
        print("Error: Path traversal detected", file=sys.stderr)
        return False
    
    try:
        # Create temp file in same directory with restrictive permissions (0600)
        dir_fd = os.open(base_dir, os.O_RDONLY | os.O_CLOEXEC)
        try:
            # Open temp file with O_CREAT|O_EXCL for exclusive creation and O_NOFOLLOW to prevent symlink attacks
            fd = os.open(
                "temp_config.tmp",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0),
                mode=0o600,
                dir_fd=dir_fd
            )
            
            try:
                # Convert content to bytes using UTF-8 encoding
                content_bytes = content.encode('utf-8')
                
                # Write content
                bytes_written = os.write(fd, content_bytes)
                
                if bytes_written != len(content_bytes):
                    raise IOError("Incomplete write")
                
                # Ensure data is flushed to disk
                os.fsync(fd)
            finally:
                os.close(fd)
            
            # Atomic rename to final location
            temp_path = os.path.join(base_dir, "temp_config.tmp")
            os.replace(temp_path, file_path)
            
            return True
            
        finally:
            os.close(dir_fd)
            
    except FileExistsError:
        # Temp file already exists, try cleanup and fail
        try:
            os.unlink(os.path.join(base_dir, "temp_config.tmp"))
        except:
            pass
        print("Error: Temporary file conflict", file=sys.stderr)
        return False
        
    except Exception as e:
        # Clean up temp file on error
        try:
            os.unlink(os.path.join(base_dir, "temp_config.tmp"))
        except:
            pass
        print("Error: File operation failed", file=sys.stderr)
        return False


if __name__ == "__main__":
    # Test case 1: Normal write
    print(f"Test 1: {write_config_file('config1.txt', 'important_config')}")
    
    # Test case 2: Empty content
    print(f"Test 2: {write_config_file('config2.txt', '')}")
    
    # Test case 3: Multi-line content
    print(f"Test 3: {write_config_file('config3.txt', 'line1\\\\nline2\\\\nline3')}")
    
    # Test case 4: None filename (should fail)
    print(f"Test 4: {write_config_file(None, 'important_config')}")
    
    # Test case 5: Path traversal attempt (should fail)
    print(f"Test 5: {write_config_file('../../../etc/passwd', 'important_config')}")
