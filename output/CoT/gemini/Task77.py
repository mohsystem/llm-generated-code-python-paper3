import ftplib
import sys
import os

def download_file(hostname, username, password, remote_file):
    """
    Connects to an FTP server and downloads a file.

    Args:
        hostname (str): The FTP server hostname or IP address.
        username (str): The username for authentication.
        password (str): The password for authentication.
        remote_file (str): The full path of the file to download from the server.
    
    Returns:
        bool: True if download was successful, False otherwise.
    """
    # WARNING: Standard FTP sends credentials and data in plaintext.
    # For production systems, always use FTPS (FTP over SSL/TLS) or SFTP.

    # Security: Prevent path traversal attacks.
    # Use only the basename of the remote file for the local filename.
    local_filename = os.path.basename(remote_file)
    if not local_filename:
        print(f"Error: Could not determine a local filename from remote path: {remote_file}", file=sys.stderr)
        return False
        
    try:
        with ftplib.FTP(hostname, timeout=10) as ftp:
            ftp.login(username, password)
            print(f"Logged in successfully to {hostname}")
            
            print(f"Downloading file {remote_file} to {local_filename}...")
            
            with open(local_filename, 'wb') as local_file_handle:
                # Use retrbinary for downloading files
                resp = ftp.retrbinary(f'RETR {remote_file}', local_file_handle.write)
                
                if resp.startswith('226'):
                    print("File downloaded successfully.")
                    return True
                else:
                    print(f"Error downloading file: {resp}", file=sys.stderr)
                    return False
                
    except ftplib.all_errors as e:
        print(f"FTP error: {e}", file=sys.stderr)
        # Clean up the potentially empty local file if an error occurred
        if os.path.exists(local_filename):
            os.remove(local_filename)
        return False

def main():
    """Main function to handle command-line arguments or run test cases."""
    # WARNING: Passing credentials as command-line arguments is insecure.
    # They can be viewed by other users on the system via the process list.
    # This is for demonstration purposes only.
    if len(sys.argv) == 5:
        hostname = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        remote_file = sys.argv[4]
        download_file(hostname, username, password, remote_file)
    else:
        print("Running test cases. Please replace placeholder values if needed.")
        print("Usage: python your_script_name.py <host> <username> <password> <remoteFilePath>")

        # Test cases use a public test FTP server.
        # Note: The remote files do not exist, so download will fail,
        # but connection and login should succeed, demonstrating the process.
        
        # Test Case 1: Example with valid-looking data
        print("\n--- Test Case 1 ---")
        download_file("ftp.dlptest.com", "dlpuser", "rNrKYTX9g7z3RgJR", "some-file.txt")

        # Test Case 2: Example with a file in a subdirectory
        print("\n--- Test Case 2 ---")
        download_file("ftp.dlptest.com", "dlpuser", "rNrKYTX9g7z3RgJR", "folder/some-other-file.zip")

        # Test Case 3: Invalid Host (will fail to connect)
        print("\n--- Test Case 3 ---")
        download_file("invalid.ftp.host", "user", "pass", "file.txt")

        # Test Case 4: Invalid Credentials (will fail to login)
        print("\n--- Test Case 4 ---")
        download_file("ftp.dlptest.com", "wronguser", "wrongpass", "file.txt")

        # Test Case 5: File Not Found (will fail to download)
        print("\n--- Test Case 5 ---")
        download_file("ftp.dlptest.com", "dlpuser", "rNrKYTX9g7z3RgJR", "non-existent-file.dat")


if __name__ == "__main__":
    main()