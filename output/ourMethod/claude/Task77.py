
#!/usr/bin/env python3
"""\nSecure FTP file downloader with comprehensive input validation and security controls.\nAll security-sensitive operations are documented and validated.\n"""

import sys
import os
import ftplib
import ssl
from pathlib import Path
from typing import Optional
import re

def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname to prevent injection attacks.

    Args:
        hostname: The hostname to validate

    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False

    # Allow domain names and IPv4 addresses only
    # Reject special characters that could be used in injection attacks
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$|'
        r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    )

    return bool(hostname_pattern.match(hostname))

def validate_username(username: str) -> bool:
    """\n    Validate username to prevent injection attacks.\n    \n    Args:\n        username: The username to validate\n        \n    Returns:\n        True if valid, False otherwise\n    """
    if not username or len(username) > 128:
        return False
    
    # Allow alphanumeric, underscore, hyphen, dot, and @ symbol
    # Reject control characters and special characters that could be malicious
    username_pattern = re.compile(r'^[a-zA-Z0-9._@-]+$')
    return bool(username_pattern.match(username))

def validate_filename(filename: str) -> bool:
    """
    Validate remote filename to prevent path traversal attacks.

    Args:
        filename: The filename to validate

    Returns:
        True if valid, False otherwise
    """
    if not filename or len(filename) > 255:
        return False

    # Reject path traversal attempts and absolute paths
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return False

    # Reject null bytes and control characters
    if '\\0' in filename or any(ord(c) < 32 for c in filename):
        return False

    # Allow only safe characters in filenames
    filename_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
    return bool(filename_pattern.match(filename))


def secure_file_write(local_path: Path, data: bytes) -> bool:
    """
    Securely write data to a file using atomic operations.

    Args:
        local_path: The destination file path
        data: The data to write

    Returns:
        True if successful, False otherwise
    """
    try:
        # Write to temporary file first to avoid TOCTOU issues
        temp_path = local_path.with_suffix(local_path.suffix + '.tmp')

        # Use 'xb' mode: create new file, fail if exists, binary mode
        # This prevents race conditions where file could be swapped
        with open(temp_path, 'xb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is written to disk

        # Set restrictive permissions (owner read/write only)
        os.chmod(temp_path, 0o600)

        # Atomically rename temp file to final destination
        # This prevents partial file exposure
        temp_path.replace(local_path)

        return True

    except FileExistsError:
        print(f"Error: File {local_path} already exists", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error writing file: {e}", file=sys.stderr)
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        return False


def download_ftp_file(
        hostname: str,
        username: str,
        password: str,
        remote_filename: str
) -> bool:
    """
    Download a file from FTP server with comprehensive security validation.

    Args:
        hostname: FTP server hostname
        username: FTP username
        password: FTP password
        remote_filename: Name of file to download

    Returns:
        True if successful, False otherwise
    """
    ftp: Optional[ftplib.FTP_TLS] = None

    try:
        # Validate all inputs before processing
        if not validate_hostname(hostname):
            print("Error: Invalid hostname format", file=sys.stderr)
            return False

        if not validate_username(username):
            print("Error: Invalid username format", file=sys.stderr)
            return False

        if not password or len(password) > 1024:
            print("Error: Invalid password length", file=sys.stderr)
            return False

        if not validate_filename(remote_filename):
            print("Error: Invalid filename or path traversal attempt detected", file=sys.stderr)
            return False

        # Resolve current directory and validate write permissions
        current_dir = Path.cwd()
        local_path = current_dir / remote_filename

        # Ensure the resolved path is within current directory (prevent path traversal)
        try:
            local_path.resolve().relative_to(current_dir.resolve())
        except ValueError:
            print("Error: Path traversal attempt detected", file=sys.stderr)
            return False

        # Check if file already exists to prevent overwriting
        if local_path.exists():
            print(f"Error: File {remote_filename} already exists in current directory", file=sys.stderr)
            return False

        # Create SSL context with secure defaults and certificate verification
        # This enforces TLS 1.2+ and proper certificate validation
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Enforce TLS 1.2 or higher to prevent downgrade attacks
        if hasattr(ssl, "TLSVersion"):
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            # Fallback for older Python versions
            ssl_context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
            ssl_context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
            ssl_context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
            ssl_context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)

        # Use FTP_TLS (FTPS) for encrypted connections
        # Regular FTP transmits credentials in plaintext
        ftp = ftplib.FTP_TLS(context=ssl_context, timeout=30)

        # Set encoding to UTF-8 for safe string handling
        ftp.encoding = 'utf-8'

        print(f"Connecting to {hostname}...")
        ftp.connect(hostname, 21)

        # Secure the control connection
        ftp.auth()

        # Login with provided credentials
        # Note: Password should come from secure vault/env var in production
        print(f"Logging in as {username}...")
        ftp.login(username, password)

        # Secure the data connection
        ftp.prot_p()

        print(f"Downloading {remote_filename}...")

        # Download file content to memory first (with size limit)
        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB limit to prevent DoS
        file_data = bytearray()

        def write_callback(data: bytes) -> None:
            """Callback to accumulate file data with size validation."""
            nonlocal file_data
            if len(file_data) + len(data) > MAX_FILE_SIZE:
                raise ValueError("File size exceeds maximum allowed limit")
            file_data.extend(data)

        # RETR command downloads the file in binary mode
        ftp.retrbinary(f'RETR {remote_filename}', write_callback)

        # Securely write downloaded data to disk
        if not secure_file_write(local_path, bytes(file_data)):
            return False

        print(f"Successfully downloaded {remote_filename} ({len(file_data)} bytes)")

        # Close FTP connection
        ftp.quit()

        return True

    except ftplib.error_perm as e:
        print(f"FTP permission error: {e}", file=sys.stderr)
        return False
    except ftplib.error_temp as e:
        print(f"FTP temporary error: {e}", file=sys.stderr)
        return False
    except ssl.SSLError as e:
        print(f"SSL/TLS error: {e}", file=sys.stderr)
        return False
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Network or I/O error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return False
    finally:
        # Ensure FTP connection is closed even if errors occur
        if ftp is not None:
            try:
                ftp.close()
            except Exception:
                pass


def main() -> int:
    """\n    Main entry point with command-line argument validation.\n    \n    Returns:\n        0 on success, 1 on failure\n    """
    # Validate command-line argument count
    if len(sys.argv) != 5:
        print("Usage: python solution.py <hostname> <username> <password> <remote_filename>", file=sys.stderr)
        print("\\nSecurity Notes:", file=sys.stderr)
        print("- Credentials should be retrieved from secure vault/env vars in production", file=sys.stderr)
        print("- This implementation uses FTPS (FTP over TLS) for encrypted connections", file=sys.stderr)
        print("- All inputs are validated to prevent injection attacks", file=sys.stderr)
        print("- Path traversal attempts are detected and blocked", file=sys.stderr)
        return 1
    
    # Extract arguments (do not log password)
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    remote_filename = sys.argv[4]
    
    # Execute download with comprehensive error handling
    success = download_ftp_file(hostname, username, password, remote_filename)
    
    return 0 if success else 1


# Test cases for validation functions
if __name__ == "__main__":
    # Run main program if executed directly
    if len(sys.argv) > 1:
        sys.exit(main())
    
    # Run test cases if no arguments provided
    print("Running security validation tests...\\n")
    
    # Test 1: Valid hostname validation
    print("Test 1: Hostname validation")
    assert validate_hostname("ftp.example.com") == True
    assert validate_hostname("192.168.1.1") == True
    assert validate_hostname("ftp-server.test.org") == True
    assert validate_hostname("../../etc/passwd") == False
    assert validate_hostname("host;rm -rf /") == False
    print("✓ Hostname validation tests passed\\n")
    
    # Test 2: Username validation
    print("Test 2: Username validation")
    assert validate_username("user123") == True
    assert validate_username("test.user@domain") == True
    assert validate_username("user_name-123") == True
    assert validate_username("user;drop table") == False
    assert validate_username("user\\x00admin") == False
    print("✓ Username validation tests passed\\n")
    
    # Test 3: Filename validation
    print("Test 3: Filename validation")
    assert validate_filename("document.txt") == True
    assert validate_filename("file-123.pdf") == True
    assert validate_filename("data_2024.csv") == True
    assert validate_filename("../../../etc/passwd") == False
    assert validate_filename("/etc/shadow") == False
    assert validate_filename("file\\0.txt") == False
    print("✓ Filename validation tests passed\\n")
    
    # Test 4: Path traversal prevention
    print("Test 4: Path traversal prevention")
    assert validate_filename("normal_file.txt") == True
    assert validate_filename("..") == False
    assert validate_filename("../file.txt") == False
    assert validate_filename("dir/../file.txt") == False
    print("✓ Path traversal prevention tests passed\\n")
    
    # Test 5: Length validation
    print("Test 5: Input length validation")
    assert validate_hostname("a" * 253) == True
    assert validate_hostname("a" * 254) == False
    assert validate_username("a" * 128) == True
    assert validate_username("a" * 129) == False
    assert validate_filename("a" * 255) == True
    assert validate_filename("a" * 256) == False
    print("✓ Length validation tests passed\\n")
    
    print("All security validation tests passed successfully!")
    print("\\nTo download a file, run:")
    print("python solution.py <hostname> <username> <password> <remote_filename>")
