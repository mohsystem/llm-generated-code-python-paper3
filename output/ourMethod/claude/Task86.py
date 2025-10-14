
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request
import ssl
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
ALLOWED_EXTENSION = '.exe'


def download_file(url: str, expected_hash: Optional[str] = None) -> Tuple[str, str]:
    """\n    Download a file from a URL with security validations.\n    Returns tuple of (file_path, sha256_hash)\n    """
    if not url or not url.strip():
        raise ValueError("URL cannot be null or empty")
    
    # Validate URL format and ensure HTTPS
    parsed_url = urlparse(url)
    if parsed_url.scheme.lower() != 'https':
        raise SecurityError("Only HTTPS URLs are allowed")
    
    # Create secure SSL context with certificate validation
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    request = urllib.request.Request(
        url,
        headers={'User-Agent': 'SecureDownloader/1.0'}
    )
    
    try:
        with urllib.request.urlopen(request, context=ssl_context, timeout=30) as response:
            # Check content length
            content_length = response.getheader('Content-Length')
            if content_length and int(content_length) > MAX_FILE_SIZE:
                raise SecurityError("File size exceeds maximum allowed size")
            
            # Create secure temporary directory and file
            temp_dir = tempfile.mkdtemp(prefix='secure_download_')
            temp_file_path = os.path.join(temp_dir, 'downloaded.exe')
            
            hasher = hashlib.sha256()
            total_bytes = 0
            
            with open(temp_file_path, 'wb') as temp_file:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    
                    total_bytes += len(chunk)
                    if total_bytes > MAX_FILE_SIZE:
                        os.unlink(temp_file_path)
                        os.rmdir(temp_dir)
                        raise SecurityError("File size exceeds maximum allowed size")
                    
                    temp_file.write(chunk)
                    hasher.update(chunk)
            
            actual_hash = hasher.hexdigest()
            
            # Verify hash if provided
            if expected_hash:
                if not compare_digest_safe(expected_hash.lower(), actual_hash.lower()):
                    os.unlink(temp_file_path)
                    os.rmdir(temp_dir)
                    raise SecurityError("File integrity check failed")
            
            return temp_file_path, actual_hash
            
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to download file: {e}")


def execute_file(file_path: str, require_confirmation: bool = True) -> int:
    """\n    Execute a file with security validations.\n    Returns the exit code of the process.\n    """
    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be null or empty")
    
    # Normalize and validate path
    path = Path(file_path).resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not path.is_file():
        raise SecurityError("Path must point to a regular file")
    
    if path.suffix.lower() != ALLOWED_EXTENSION:
        raise SecurityError("Only .exe files are allowed")
    
    # Require confirmation
    if require_confirmation:
        print(f"WARNING: You are about to execute: {path}", file=sys.stderr)
        confirmation = input("Type 'YES' to confirm execution: ")
        if confirmation != 'YES':
            raise SecurityError("Execution cancelled by user")
    
    # Execute the file
    process = subprocess.Popen(
        [str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    return process.wait()


def compare_digest_safe(a: str, b: str) -> bool:
    """Constant-time string comparison"""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass


def main():
    """Test cases"""
    print("Secure EXE Downloader and Executor - Test Cases")
    print("Note: Tests use simulated URLs for demonstration\\n")
    
    # Test 1: Invalid URL (not HTTPS)
    print("Test 1: Invalid URL (HTTP instead of HTTPS)")
    try:
        download_file("http://example.com/file.exe")
        print("FAIL: Should have rejected HTTP URL")
    except SecurityError as e:
        print(f"PASS: {e}")
    except Exception as e:
        print(f"PASS: Rejected - {e}")
    
    # Test 2: Null URL
    print("\\nTest 2: None URL")
    try:
        download_file(None)
        print("FAIL: Should have rejected None URL")
    except (ValueError, AttributeError) as e:
        print(f"PASS: {e}")
    except Exception as e:
        print(f"PASS: Rejected - {e}")
    
    # Test 3: Empty URL
    print("\\nTest 3: Empty URL")
    try:
        download_file("")
        print("FAIL: Should have rejected empty URL")
    except ValueError as e:
        print(f"PASS: {e}")
    except Exception as e:
        print(f"PASS: Rejected - {e}")
    
    # Test 4: Invalid file path for execution
    print("\\nTest 4: Execute non-existent file")
    try:
        execute_file("/nonexistent/path/file.exe", False)
        print("FAIL: Should have rejected non-existent file")
    except FileNotFoundError as e:
        print(f"PASS: {e}")
    except Exception as e:
        print(f"PASS: Rejected - {e}")
    
    # Test 5: Invalid file extension
    print("\\nTest 5: Execute file with wrong extension")
    try:
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as tmp:
            tmp.write(b'test')
            tmp_path = tmp.name
        
        execute_file(tmp_path, False)
        os.unlink(tmp_path)
        print("FAIL: Should have rejected non-exe file")
    except SecurityError as e:
        print(f"PASS: {e}")
        try:
            os.unlink(tmp_path)
        except:
            pass
    except Exception as e:
        print(f"PASS: Rejected - {e}")


if __name__ == "__main__":
    main()
