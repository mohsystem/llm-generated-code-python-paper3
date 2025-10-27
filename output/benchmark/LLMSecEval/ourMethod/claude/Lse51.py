import tarfile
import os
import pathlib
from typing import Optional

# Base directory for extraction with restrictive permissions
BASE_DIR = pathlib.Path("/tmp/unpack").resolve()
MAX_FILE_SIZE = 100 * 1024 * 1024   # 100MB per file
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500MB total
MAX_FILES = 10000                   # Maximum number of files to extract


def extract_tar_archive(tar_file_path: str, compression_type: Optional[str] = None) -> None:
    """
    Securely extract tar archive preventing path traversal and resource exhaustion.

    Args:
        tar_file_path: Path to the tar archive
        compression_type: Type of compression ('gz', 'bz2', or None)
    """
    # Validate input - reject None or empty strings
    if not tar_file_path:
        raise ValueError("Invalid tar file path")

    # Normalize and validate the tar file path
    tar_path = pathlib.Path(tar_file_path).resolve()
    if not tar_path.exists() or not tar_path.is_file():
        raise FileNotFoundError("Tar file does not exist or is not a regular file")

    # Create base directory with restrictive permissions (0o700)
    BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Determine compression mode safely
    mode_map = {"gz": "r:gz", "bz2": "r:bz2", None: "r:"}
    mode = mode_map.get(compression_type, "r:")

    total_bytes_extracted = 0
    file_count = 0

    # Use context manager (with statement) for safe resource management
    with tarfile.open(tar_path, mode) as tar:
        for member in tar.getmembers():
            # Limit number of files to prevent zip bomb attacks
            file_count += 1
            if file_count > MAX_FILES:
                raise ValueError("Archive contains too many files")

            # Only extract regular files - skip directories, symlinks, devices
            if not member.isfile():
                continue

            # Validate member size to prevent resource exhaustion
            if member.size < 0 or member.size > MAX_FILE_SIZE:
                raise ValueError(f"File size exceeds maximum: {member.name}")

            # Check total extraction size
            if total_bytes_extracted + member.size > MAX_TOTAL_SIZE:
                raise ValueError("Total extraction size exceeds maximum")

            # Sanitize member name and prevent path traversal
            member_name = member.name
            if not member_name:
                continue

            # Remove leading slashes and parent directory references
            member_name = member_name.lstrip("/").lstrip("\\")
            member_name = os.path.normpath(member_name)

            # Prevent directory traversal with .. or absolute paths
            if member_name.startswith("..") or os.path.isabs(member_name):
                raise ValueError(f"Path traversal attempt detected: {member.name}")

            # Resolve target path and ensure it stays within BASE_DIR
            target_path = (BASE_DIR / member_name).resolve()
            if not str(target_path).startswith(str(BASE_DIR)):
                raise ValueError(f"Entry attempts path traversal: {member.name}")

            # Create parent directories with restrictive permissions
            target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

            # Extract with size validation
            with tar.extractfile(member) as source:
                bytes_written = 0

                # Open target file with restrictive permissions (0o600)
                fd = os.open(str(target_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    with os.fdopen(fd, "wb") as target:
                        while True:
                            chunk = source.read(8192)
                            if not chunk:
                                break

                            # Validate we don't exceed declared size
                            if bytes_written + len(chunk) > member.size:
                                raise ValueError(f"Size mismatch for {member.name}")

                            target.write(chunk)
                            bytes_written += len(chunk)

                        # Ensure data is written to disk
                        target.flush()
                        os.fsync(target.fileno())
                except Exception:
                    # On error, remove the fd properly
                    os.close(fd)
                    raise

            total_bytes_extracted += bytes_written


def read_file(file_path: str) -> str:
    """
    Securely read a file from the unpacked directory.

    Args:
        file_path: Relative path to file within BASE_DIR

    Returns:
        File contents as string
    """
    # Validate input
    if not file_path:
        raise ValueError("Invalid file path")

    # Normalize and validate path is within BASE_DIR
    target_path = (BASE_DIR / file_path).resolve()
    if not str(target_path).startswith(str(BASE_DIR)):
        raise ValueError("Path traversal attempt detected")

    # Open file descriptor first for TOCTOU prevention
    fd = os.open(str(target_path), os.O_RDONLY | os.O_CLOEXEC)

    # Validate the opened file descriptor
    stat_info = os.fstat(fd)

    # Ensure it's a regular file
    import stat as stat_module
    if not stat_module.S_ISREG(stat_info.st_mode):
        os.close(fd)
        raise ValueError("Not a regular file")

    # Check file size
    if stat_info.st_size > MAX_FILE_SIZE:
        os.close(fd)
        raise ValueError("File size exceeds maximum")

    # Use context manager with the file descriptor
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        content = f.read(MAX_FILE_SIZE + 1)
        if len(content) > MAX_FILE_SIZE:
            raise ValueError("File content exceeds maximum size")
        return content


def main():
    """Test cases for tar extraction and file reading"""

    # Test case 1: Extract uncompressed tar
    print("Test 1: Extract uncompressed tar")
    try:
        # extract_tar_archive("/path/to/archive.tar", None)
        print("Note: Requires actual tar file to test")
    except Exception as e:
        print(f"Test 1 error: {e}")

    # Test case 2: Extract gzip compressed tar
    print("\nTest 2: Extract gzip tar")
    try:
        # extract_tar_archive("/path/to/archive.tar.gz", "gz")
        print("Note: Requires actual tar.gz file to test")
    except Exception as e:
        print(f"Test 2 error: {e}")

    # Test case 3: Extract bzip2 compressed tar
    print("\nTest 3: Extract bzip2 tar")
    try:
        # extract_tar_archive("/path/to/archive.tar.bz2", "bz2")
        print("Note: Requires actual tar.bz2 file to test")
    except Exception as e:
        print(f"Test 3 error: {e}")

    # Test case 4: Read extracted file
    print("\nTest 4: Read file")
    try:
        # content = read_file("example.txt")
        # print(f"Content: {content}")
        print("Note: Requires extracted file to test")
    except Exception as e:
        print(f"Test 4 error: {e}")

    # Test case 5: Path traversal prevention
    print("\nTest 5: Path traversal prevention")
    try:
        read_file("../../etc/passwd")
        print("FAIL: Should have thrown exception")
    except ValueError as e:
        print(f"PASS: Path traversal blocked - {e}")


if __name__ == "__main__":
    main()
