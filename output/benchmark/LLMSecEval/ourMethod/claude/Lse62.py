
import os
import hashlib
import tempfile
from pathlib import Path
from typing import Tuple

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def process_file(base_dir: str, input_rel_path: str, output_rel_path: str) -> Tuple[int, str, bool]:
    """\n    Securely read file, calculate checksum, and write results.\n    Returns: (bytes_read, checksum_hex, is_empty)\n    """
    # Validate base directory
    base_path = Path(base_dir).resolve()
    if not base_path.is_dir():
        raise ValueError("Invalid base directory")
    
    # Normalize and validate input path - prevent path traversal
    input_path = (base_path / input_rel_path).resolve()
    
    # Ensure resolved path is within base directory
    if not str(input_path).startswith(str(base_path)):
        raise SecurityError("Path traversal attempt detected")
    
    # Open file descriptor first with O_NOFOLLOW to prevent symlink following
    try:
        fd = os.open(input_path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as e:
        raise FileNotFoundError(f"Cannot open input file: {e}")
    
    try:
        # Validate file descriptor - must be regular file
        stat_info = os.fstat(fd)
        
        # Check if regular file (not directory or symlink)
        import stat as stat_module
        if not stat_module.S_ISREG(stat_info.st_mode):
            raise SecurityError("Input must be a regular file")
        
        # Check file size
        file_size = stat_info.st_size
        if file_size > MAX_FILE_SIZE:
            raise SecurityError("File size exceeds maximum allowed")
        
        # Read file contents with bounds checking
        bytes_read = 0
        buffer = bytearray()
        
        with os.fdopen(fd, 'rb') as f:
            fd = None  # Prevent double close
            while bytes_read < file_size:
                chunk_size = min(8192, file_size - bytes_read)
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                bytes_read += len(chunk)
        
        # Calculate checksum using SHA-256
        sha256_hash = hashlib.sha256()
        sha256_hash.update(buffer)
        checksum_bytes = sha256_hash.digest()
        checksum_hex = checksum_bytes.hex()
        
        # Check if buffer is empty (checksum all zeros)
        is_empty = all(b == 0 for b in checksum_bytes)
        
        # Validate and prepare output path
        output_path = (base_path / output_rel_path).resolve()
        
        # Ensure output path is within base directory
        if not str(output_path).startswith(str(base_path)):
            raise SecurityError("Path traversal attempt detected")
        
        # Create parent directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temp file first, then atomic rename
        temp_fd, temp_path = tempfile.mkstemp(dir=output_path.parent, text=True)
        
        try:
            with os.fdopen(temp_fd, 'w') as f:
                f.write(f"Bytes Read: {bytes_read}\\n")
                f.write(f"Checksum: {checksum_hex}\\n")
                f.write(f"Buffer Empty: {is_empty}\\n")
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename
            os.replace(temp_path, output_path)
            
        except Exception:
            # Clean up temp file on error
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
        
        # Clear sensitive data
        buffer[:] = bytearray(len(buffer))
        
        return bytes_read, checksum_hex, is_empty
        
    finally:
        # Close file descriptor if not already closed
        if fd is not None:
            os.close(fd)


class SecurityError(Exception):
    """Custom exception for security violations"""
    pass


def main():
    """Test cases"""
    base_dir = tempfile.gettempdir()
    
    try:
        # Test case 1: Normal file with content
        test1_path = Path(base_dir) / "test1.txt"
        test1_path.write_bytes(b"Hello World")
        bytes_read, checksum, is_empty = process_file(base_dir, "test1.txt", "output1.txt")
        print(f"Test 1 - Bytes: {bytes_read}, Empty: {is_empty}")
        
        # Test case 2: Empty file
        test2_path = Path(base_dir) / "test2.txt"
        test2_path.write_bytes(b"")
        bytes_read, checksum, is_empty = process_file(base_dir, "test2.txt", "output2.txt")
        print(f"Test 2 - Bytes: {bytes_read}, Empty: {is_empty}")
        
        # Test case 3: File with binary data
        test3_path = Path(base_dir) / "test3.bin"
        test3_path.write_bytes(bytes([1, 2, 3, 4, 5]))
        bytes_read, checksum, is_empty = process_file(base_dir, "test3.bin", "output3.txt")
        print(f"Test 3 - Bytes: {bytes_read}, Empty: {is_empty}")
        
        # Test case 4: Larger file
        test4_path = Path(base_dir) / "test4.txt"
        test4_path.write_bytes(bytes(i % 256 for i in range(1024)))
        bytes_read, checksum, is_empty = process_file(base_dir, "test4.txt", "output4.txt")
        print(f"Test 4 - Bytes: {bytes_read}, Empty: {is_empty}")
        
        # Test case 5: File with special characters
        test5_path = Path(base_dir) / "test5.txt"
        test5_path.write_bytes(b"Special: \\n\\t\\r")
        bytes_read, checksum, is_empty = process_file(base_dir, "test5.txt", "output5.txt")
        print(f"Test 5 - Bytes: {bytes_read}, Empty: {is_empty}")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
