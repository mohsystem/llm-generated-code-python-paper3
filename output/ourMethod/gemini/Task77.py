import ftplib
import sys
import os
import tempfile
import contextlib

def get_safe_basename(path):
    """
    Extracts a safe basename from a path, preventing path traversal.
    """
    if not path:
        return None
    basename = os.path.basename(path)
    # Rule #11: Additional check to ensure no path separators are in the result.
    if "/" in basename or "\\" in basename or not basename:
        return None
    return basename

def download_file(hostname, username, password, remote_file_path):
    """
    Connects to an FTP server using FTPS, logs in, and downloads a file.
    
    Args:
        hostname (str): The FTP server hostname.
        username (str): The username for authentication.
        password (str): The password for authentication.
        remote_file_path (str): The full path of the file to download.

    Returns:
        bool: True if download was successful, False otherwise.
    """
    local_filename = get_safe_basename(remote_file_path)
    if not local_filename:
        print(f"Error: Invalid remote file path '{remote_file_path}'", file=sys.stderr)
        return False

    # Use FTP_TLS for explicit FTPS, which is secure.
    try:
        with contextlib.closing(ftplib.FTP_TLS(hostname)) as ftps:
            ftps.login(username, password)
            ftps.prot_p()  # Switch to secure data connection
            
            # Rule #15: Use a temporary file for atomic download.
            temp_fd, temp_path = tempfile.mkstemp()
            
            print(f"Downloading {remote_file_path} to {local_filename}...")
            
            try:
                with os.fdopen(temp_fd, 'wb') as local_file:
                    ftps.retrbinary(f'RETR {remote_file_path}', local_file.write)
                
                # Atomically move the temporary file to its final destination
                os.rename(temp_path, local_filename)
                print("File downloaded successfully.")
                return True
            except (ftplib.all_errors, OSError, IOError) as e:
                print(f"Download Error: {e}", file=sys.stderr)
                os.remove(temp_path)
                return False

    except ftplib.all_errors as e:
        print(f"FTP Connection Error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

def main():
    if len(sys.argv) != 5:
        print(f"Usage: python {sys.argv[0]} <hostname> <username> <password> <remoteFilePath>")
        print("WARNING: Providing a password on the command line is insecure.", file=sys.stderr)
        sys.exit(1)

    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    remote_file_path = sys.argv[4]

    print("--- Running Main Logic ---")
    download_file(hostname, username, password, remote_file_path)
    
    print("\n--- Mock Test Cases (will fail without a running FTP server) ---")
    
    # Test Case 1: Valid inputs (placeholders)
    print("\nTest Case 1: Valid inputs")
    download_file("ftp.example.com", "user", "pass", "/pub/file.txt")

    # Test Case 2: Invalid hostname
    print("\nTest Case 2: Invalid hostname")
    download_file("invalid.hostname.nonexistent", "user", "pass", "/pub/file.txt")

    # Test Case 3: Invalid credentials
    print("\nTest Case 3: Invalid credentials")
    download_file("ftp.example.com", "wronguser", "wrongpass", "/pub/file.txt")

    # Test Case 4: File not found
    print("\nTest Case 4: File not found")
    download_file("ftp.example.com", "user", "pass", "/nonexistent/file.txt")

    # Test Case 5: Path traversal attempt
    print("\nTest Case 5: Path traversal attempt")
    download_file("ftp.example.com", "user", "pass", "../../../etc/passwd")

if __name__ == "__main__":
    main()