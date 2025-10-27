
import os
import secrets
import base64
from pathlib import Path
from typing import BinaryIO

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
PDF_MAGIC = b'%PDF'
def upload_pdf(file_stream: BinaryIO, original_filename: str, file_size: int) -> str:
    """
    Securely upload a PDF file with validation and path traversal prevention.

    Args:
        file_stream: Binary file stream to read from
        original_filename: Original name of the uploaded file
        file_size: Size of the file in bytes

    Returns:
        str: The secure filename used for storage

    Raises:
        ValueError: If validation fails
        IOError: If file operations fail
    """
    # Input validation: check file size
    if file_size <= 0 or file_size > MAX_FILE_SIZE:
        raise ValueError("Invalid file size")

    # Validate filename is not None and doesn't contain path separators
    if (
            not original_filename
            or ".." in original_filename
            or "/" in original_filename
            or "\\" in original_filename
    ):
        raise ValueError("Invalid filename")

    # Check file extension
    if not original_filename.lower().endswith(".pdf"):
        raise ValueError("Only PDF files are allowed")

    # Create uploads directory with restricted permissions if it doesn't exist
    upload_path = Path(UPLOAD_DIR).resolve()
    if not upload_path.exists():
        upload_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Generate secure random filename to prevent collisions and attacks
    random_bytes = secrets.token_bytes(16)
    safe_filename = (
            base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=") + ".pdf"
    )

    # Construct target path and validate it's within upload directory
    target_path = (upload_path / safe_filename).resolve()
    if not str(target_path).startswith(str(upload_path)):
        raise SecurityError("Path traversal attempt detected")

    # Read file content with size limit enforcement
    file_content = bytearray()
    chunk_size = 8192
    total_read = 0

    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > MAX_FILE_SIZE:
            raise IOError("File size exceeds maximum allowed size")
        file_content.extend(chunk)

    # Validate PDF magic bytes
    if len(file_content) < 4:
        raise ValueError("File too small to be a valid PDF")

    if not file_content.startswith(PDF_MAGIC):
        raise ValueError("File is not a valid PDF")

    # Write to temporary file first, then atomically move to final location
    temp_fd = None
    temp_path = None

    try:
        # Create temp file with O_EXCL to prevent race conditions
        temp_path = Path(upload_path / f"temp_{safe_filename}")
        temp_fd = os.open(
            str(temp_path),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
            0o600,  # Restrictive permissions: owner read/write only
        )

        # Write content to temp file
        bytes_written = 0
        while bytes_written < len(file_content):
            n = os.write(temp_fd, file_content[bytes_written:])
            bytes_written += n

        # Ensure data is written to disk
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        # Atomic move to final location
        os.replace(str(temp_path), str(target_path))

        return safe_filename

    except Exception:
        # Clean up on error
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise
    finally:
        if temp_fd is not None:
            os.close(temp_fd)


def main():
    """Test cases for PDF upload functionality"""
    import io

    print("PDF Upload Test Cases:")

    # Test case 1: Valid PDF file
    try:
        valid_pdf = bytearray(100)
        valid_pdf[0:4] = b"%PDF"
        stream1 = io.BytesIO(bytes(valid_pdf))
        result1 = upload_pdf(stream1, "document.pdf", len(valid_pdf))
        print(f"Test 1 PASSED: {result1}")
    except Exception as e:
        print(f"Test 1 FAILED: {e}")

    # Test case 2: File too large
    try:
        upload_pdf(io.BytesIO(b""), "large.pdf", 20 * 1024 * 1024)
        print("Test 2 FAILED: Should reject large file")
    except ValueError:
        print("Test 2 PASSED: Rejected large file")
    except Exception as e:
        print(f"Test 2 FAILED: {e}")

    # Test case 3: Path traversal attempt
    try:
        valid_pdf = bytearray(100)
        valid_pdf[0:4] = b"%PDF"
        upload_pdf(
            io.BytesIO(bytes(valid_pdf)), "../../../etc/passwd.pdf", len(valid_pdf)
        )
        print("Test 3 FAILED: Should reject path traversal")
    except ValueError:
        print("Test 3 PASSED: Rejected path traversal")
    except Exception as e:
        print(f"Test 3 FAILED: {e}")

    # Test case 4: Invalid file extension
    try:
        valid_pdf = bytearray(100)
        valid_pdf[0:4] = b"%PDF"
        upload_pdf(io.BytesIO(bytes(valid_pdf)), "document.exe", len(valid_pdf))
        print("Test 4 FAILED: Should reject non-PDF extension")
    except ValueError:
        print("Test 4 PASSED: Rejected non-PDF extension")
    except Exception as e:
        print(f"Test 4 FAILED: {e}")

    # Test case 5: Invalid PDF magic bytes
    try:
        invalid_pdf = bytearray(100)
        upload_pdf(io.BytesIO(bytes(invalid_pdf)), "fake.pdf", len(invalid_pdf))
        print("Test 5 FAILED: Should reject invalid PDF")
    except ValueError:
        print("Test 5 PASSED: Rejected invalid PDF magic bytes")
    except Exception as e:
        print(f"Test 5 FAILED: {e}")

if __name__ == "__main__":
    main()
