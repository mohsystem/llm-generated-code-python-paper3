import ftplib
import sys
import os

def download_file_secure_ftp(host, username, password, remote_file, local_file):
    """
    Connects to an FTP server using FTP_TLS (explicit TLS) and downloads a file.

    :param host: The FTP server hostname or IP address.
    :param username: The username for authentication.
    :param password: The password for authentication.
    :param remote_file: The full path to the file to download on the server.
    :param local_file: The name of the file to save locally. Path traversal is prevented.
    :return: True if the download was successful, False otherwise.
    """
    # Security: Prevent path traversal by ensuring the local file is just a filename.
    safe_local_file = os.path.basename(local_file)
    if safe_local_file != local_file:
        print(f"Error: Local filename '{local_file}' cannot contain path separators.", file=sys.stderr)
        return False

    try:
        # Use FTP_TLS for a secure FTPS connection
        with ftplib.FTP_TLS() as ftps:
            print(f"Connecting to {host}...")
            ftps.connect(host)
            
            print("Logging in...")
            ftps.login(username, password)

            # Secure the data connection
            ftps.prot_p()
            
            print(f"Downloading {remote_file} to {safe_local_file}...")
            with open(safe_local_file, 'wb') as f:
                ftps.retrbinary(f'RETR {remote_file}', f.write)
            
            print("Download successful.")
            return True
            
    except ftplib.all_errors as e:
        print(f"An FTP error occurred: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

def main():
    # SECURITY WARNING: Passing credentials as command-line arguments is insecure.
    # They can be viewed by other users on the system via the process list and
    # may be stored in shell history. In a production environment, use a more
    # secure method like environment variables, a secure vault, or interactive prompts.
    if len(sys.argv) != 6:
        print("Usage: python script.py <host> <username> <password> <remote_file_path> <local_file_name>")
        print("\n--- Test Case Examples (replace with actual server details) ---")
        print("1. Download 'report.csv' from 'ftp.example.com':")
        print("   python script.py ftp.example.com user1 pass1 /reports/report.csv report_local.csv")
        print("2. Download 'archive.zip' from an IP address:")
        print("   python script.py 192.168.1.100 admin secret /backups/archive.zip backup.zip")
        print("3. Download 'image.jpg' from a public test server (credentials may vary):")
        print("   python script.py test.rebex.net demo password /pub/example/image.jpg example.jpg")
        print("4. Attempt to download a non-existent file:")
        print("   python script.py ftp.example.com user1 pass1 /path/to/nonexistent.file missing.txt")
        print("5. Use invalid credentials:")
        print("   python script.py ftp.example.com wronguser wrongpass /reports/report.csv report.csv")
        return

    host, username, password, remote_file, local_file = sys.argv[1:6]
    download_file_secure_ftp(host, username, password, remote_file, local_file)

if __name__ == "__main__":
    main()