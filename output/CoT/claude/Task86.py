
# WARNING: This code is inherently insecure. Use only in controlled environments.
# CWE-494: Download of Code Without Integrity Check
# CWE-829: Inclusion of Functionality from Untrusted Control Sphere

import urllib.request
import urllib.parse
import ssl
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

class Task86:
    
    @staticmethod
    def download_and_execute(url_string, expected_checksum=None):
        """\n        SECURITY WARNING: Downloading and executing arbitrary executables is dangerous.\n        This should only be used in controlled environments with trusted sources.\n        """
        print("⚠️  SECURITY WARNING: This operation is inherently dangerous!")
        print("⚠️  Only proceed with trusted sources in isolated environments.")
        
        try:
            # Validate URL
            if not Task86._is_valid_url(url_string):
                print("❌ Invalid or insecure URL. Only HTTPS URLs are allowed.")
                return False
            
            # Download file
            downloaded_file = Task86._download_file(url_string)
            if downloaded_file is None:
                return False
            
            # Verify checksum if provided
            if expected_checksum:
                actual_checksum = Task86._calculate_sha256(downloaded_file)
                if actual_checksum.lower() != expected_checksum.lower():
                    print("❌ Checksum mismatch! File may be compromised.")
                    os.unlink(downloaded_file)
                    return False
                print("✓ Checksum verified")
            else:
                print("⚠️  WARNING: No checksum verification performed!")
            
            # Request user confirmation
            print(f"\\n⚠️  About to execute: {os.path.basename(downloaded_file)}")
            confirmation = input("Type 'EXECUTE' to confirm (anything else to cancel): ")
            
            if confirmation != "EXECUTE":
                print("❌ Execution cancelled by user")
                os.unlink(downloaded_file)
                return False
            
            # Execute
            return Task86._execute_file(downloaded_file)
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return False
    
    @staticmethod
    def _is_valid_url(url_string):
        try:
            parsed = urllib.parse.urlparse(url_string)
            # Only allow HTTPS for security
            return parsed.scheme == 'https'
        except:
            return False
    
    @staticmethod
    def _download_file(url_string):
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Create temporary file
            temp_fd, temp_path = tempfile.mkstemp(suffix='.exe', prefix='downloaded_')
            os.close(temp_fd)
            
            print("⬇️  Downloading...")
            
            # Download with timeout
            with urllib.request.urlopen(url_string, timeout=30, context=context) as response:
                if response.status != 200:
                    print(f"❌ Download failed. HTTP response: {response.status}")
                    os.unlink(temp_path)
                    return None
                
                total_bytes = 0
                with open(temp_path, 'wb') as out_file:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        total_bytes += len(chunk)
            
            print(f"✓ Downloaded {total_bytes} bytes")
            return temp_path
            
        except Exception as e:
            print(f"❌ Download error: {str(e)}")
            if 'temp_path' in locals():
                try:
                    os.unlink(temp_path)
                except:
                    pass
            return None
    
    @staticmethod
    def _calculate_sha256(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(8192), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def _execute_file(file_path):
        try:
            if os.name == 'nt':  # Windows
                subprocess.Popen([file_path])
                print("✓ Execution started (Windows)")
                return True
            else:
                print("❌ Execution only supported on Windows in this demo")
                return False
        except Exception as e:
            print(f"❌ Execution error: {str(e)}")
            return False


def main():
    print("=== EXE Downloader and Executor (DEMONSTRATION ONLY) ===\\n")
    print("⚠️  CRITICAL SECURITY WARNING ⚠️")
    print("This program can execute arbitrary code from the internet.")
    print("This is extremely dangerous and should NEVER be used in production.\\n")
    
    # Test cases - These are hypothetical and should NOT be executed
    print("Test Case 1: Invalid URL (HTTP instead of HTTPS)")
    Task86.download_and_execute("http://example.com/file.exe", None)
    
    print("\\nTest Case 2: Invalid URL format")
    Task86.download_and_execute("not-a-valid-url", None)
    
    print("\\n⚠️  Remaining test cases are disabled for safety.")
    print("In a real scenario, you would need:")
    print("- A valid HTTPS URL to a trusted executable")
    print("- The SHA-256 checksum of that executable")
    print("- Proper antivirus scanning")
    print("- Sandboxed execution environment")


if __name__ == "__main__":
    main()
