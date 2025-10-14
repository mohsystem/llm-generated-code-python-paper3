
import sys
import os
from ftplib import FTP_TLS
import ssl
from pathlib import Path

class Task77:
    TIMEOUT = 30
    BUFFER_SIZE = 8192

    @staticmethod
    def download_file_secure(hostname, username, password, remote_file, local_file):
        """\n        Securely download a file from FTP server using FTPS (FTP over TLS)\n        """
        # Input validation
        if not all([hostname, username, password, remote_file, local_file]):
            print("Error: All parameters must be non-empty", file=sys.stderr)
            return False

        # Prevent path traversal attacks
        if '..' in remote_file or '..' in local_file:
            print("Error: Invalid file path detected", file=sys.stderr)
            return False

        # Validate local file path
        try:
            local_path = Path(local_file).resolve()
            if not str(local_path).startswith(str(Path.cwd())):
                print("Error: Local file must be in current directory", file=sys.stderr)
                return False
        except Exception as e:
            print(f"Error: Invalid local file path - {str(e)}", file=sys.stderr)
            return False

        try:
            print("Connecting to FTP server securely...")
            
            # Use FTPS (FTP over TLS) for secure connection
            ftps = FTP_TLS()
            ftps.encoding = 'utf-8'
            
            # Set timeout
            ftps.connect(hostname, timeout=Task77.TIMEOUT)
            
            # Login securely
            ftps.login(username, password)
            
            # Switch to secure data connection
            ftps.prot_p()
            
            print(f"Connected to {hostname}")
            print(f"Downloading {remote_file} to {local_file}")
            
            # Download file securely
            with open(local_file, 'wb') as local_fp:
                ftps.retrbinary(f'RETR {remote_file}', local_fp.write)
            
            # Set secure file permissions (owner read/write only)
            os.chmod(local_file, 0o600)
            
            ftps.quit()
            
            print("Download completed successfully")
            
            # Clear sensitive data
            password = None
            username = None
            
            return True
            
        except Exception as e:
            print(f"Error: Operation failed - {str(e)}", file=sys.stderr)
            return False

    @staticmethod
    def main():
        print("=== Test Case 1: Valid parameters ===")
        Task77.download_file_secure("ftp.example.com", "user1", "pass123",
                                    "document.pdf", "local_document.pdf")

        print("\\n=== Test Case 2: Empty hostname ===")
        Task77.download_file_secure("", "user1", "pass123", 
                                    "document.pdf", "local_document.pdf")

        print("\\n=== Test Case 3: Path traversal attempt ===")
        Task77.download_file_secure("ftp.example.com", "user1", "pass123",
                                    "../etc/passwd", "local_file.txt")

        print("\\n=== Test Case 4: None password ===")
        Task77.download_file_secure("ftp.example.com", "user1", None,
                                    "document.pdf", "local.pdf")

        print("\\n=== Test Case 5: Valid with different file ===")
        Task77.download_file_secure("secure.example.com", "admin", "securePass",
                                    "report.txt", "downloaded_report.txt")

        # Command line argument handling
        if len(sys.argv) >= 6:
            print("\\n=== Processing command line arguments ===")
            Task77.download_file_secure(sys.argv[1], sys.argv[2], sys.argv[3],
                                        sys.argv[4], sys.argv[5])

if __name__ == "__main__":
    Task77.main()
