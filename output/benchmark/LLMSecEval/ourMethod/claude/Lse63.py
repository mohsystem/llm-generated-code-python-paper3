
import os
import stat
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
BASE_DIR = "."

def process_file(input_path: str, output_path: str) -> bool:
    """\n    Reads file content and calculates checksum.\n    \n    Args:\n        input_path: Path to input file relative to BASE_DIR\n        output_path: Path to output file relative to BASE_DIR\n    \n    Returns:\n        True if operation successful, False otherwise\n    """
    # Validate and normalize paths to prevent path traversal
    try:
        base_path = Path(BASE_DIR).resolve()
        normalized_input = (base_path / input_path).resolve()
        normalized_output = (base_path / output_path).resolve()
        
        # Ensure paths stay within base directory
        if not str(normalized_input).startswith(str(base_path)) or not str(normalized_output).startswith(str(base_path)):
            print("Error: Path traversal attempt detected", file=__import__('sys').stderr)
            return False
    except (OSError, ValueError):
        print("Error: Invalid path", file=__import__('sys').stderr)
        return False
    
    buffer = None
    bytes_read = 0
    checksum = 0
    
    try:
        # Open file descriptor with O_RDONLY and O_NOFOLLOW to prevent symlink following
        fd = os.open(normalized_input, os.O_RDONLY | os.O_CLOEXEC | 
                     (os.O_NOFOLLOW if hasattr(os, 'O_NOFOLLOW') else 0))
        
        try:
            # Validate file using fstat on the opened descriptor
            st = os.fstat(fd)
            
            # Check if regular file
            if not stat.S_ISREG(st.st_mode):
                print("Error: Not a regular file", file=__import__('sys').stderr)
                return False
            
            # Check file size limit
            if st.st_size > MAX_FILE_SIZE:
                print("Error: File exceeds maximum size", file=__import__('sys').stderr)
                return False
            
            # Read file content using the validated descriptor
            with os.fdopen(fd, 'rb') as f:
                fd = -1  # Prevent double close
                buffer = f.read()
                bytes_read = len(buffer)
            
            # Calculate simple checksum (sum of all bytes mod 256)
            checksum = sum(buffer) & 0xFF
            
        finally:
            if fd >= 0:
                os.close(fd)
                
    except OSError as e:
        print("Error: Failed to read input file", file=__import__('sys').stderr)
        return False
    
    # Write result to output file using atomic operation
    result = f"Bytes read: {bytes_read}\\nChecksum: {checksum}\\nBuffer empty: {checksum == 0}\\n"
    
    try:
        # Create temp file in same directory for atomic move
        temp_fd = -1
        temp_path = None
        
        try:
            # Open temp file with restricted permissions (0600)
            temp_path = normalized_output.parent / f".tmp{os.getpid()}.txt"
            temp_fd = os.open(temp_path, 
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            0o600)
            
            # Write to temp file
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                temp_fd = -1  # Prevent double close
                f.write(result)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic move to final destination
            os.replace(temp_path, normalized_output)
            temp_path = None
            
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            if temp_path and temp_path.exists():
                temp_path.unlink()
                
    except OSError as e:
        print("Error: Failed to write output file", file=__import__('sys').stderr)
        return False
    finally:
        # Clear sensitive buffer data
        if buffer:
            buffer = bytearray(len(buffer))  # Overwrite with zeros
            del buffer
    
    return True


if __name__ == "__main__":
    import sys
    
    # Test case 1: Normal file
    try:
        Path("test1.txt").write_bytes(b"Hello World")
        print(f"Test 1: {'PASS' if process_file('test1.txt', 'output1.txt') else 'FAIL'}")
    except Exception:
        print("Test 1: FAIL - Setup error")
    
    # Test case 2: Empty file
    try:
        Path("test2.txt").write_bytes(b"")
        print(f"Test 2: {'PASS' if process_file('test2.txt', 'output2.txt') else 'FAIL'}")
    except Exception:
        print("Test 2: FAIL - Setup error")
    
    # Test case 3: File with zero checksum
    try:
        Path("test3.txt").write_bytes(bytes([0, 0, 0]))
        print(f"Test 3: {'PASS' if process_file('test3.txt', 'output3.txt') else 'FAIL'}")
    except Exception:
        print("Test 3: FAIL - Setup error")
    
    # Test case 4: Large content
    try:
        large_content = bytes([i % 256 for i in range(1000)])
        Path("test4.txt").write_bytes(large_content)
        print(f"Test 4: {'PASS' if process_file('test4.txt', 'output4.txt') else 'FAIL'}")
    except Exception:
        print("Test 4: FAIL - Setup error")
    
    # Test case 5: Path traversal attempt (should fail)
    print(f"Test 5: {'PASS' if not process_file('../test5.txt', 'output5.txt') else 'FAIL'}")
