import ftplib
import sys

def download_file_from_ftp(host, user, password, remote_file, local_file):
    """
    Connects to an FTP server and downloads a file.

    Args:
        host (str): The FTP server hostname.
        user (str): The username for login.
        password (str): The password for login.
        remote_file (str): The full path of the file to download from the server.
        local_file (str): The name of the file to save locally.

    Returns:
        bool: True if download was successful, False otherwise.
    """
    try:
        with ftplib.FTP(host) as ftp:
            ftp.login(user, password)
            print("Logged in successfully.")
            
            # Switch to passive mode
            ftp.set_pasv(True)

            print(f"Downloading file {remote_file} to {local_file}")
            with open(local_file, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_file}', f.write)
            
            print("File downloaded successfully!")
            return True
    except ftplib.all_errors as e:
        print(f"FTP error: {e}", file=sys.stderr)
        return False
    except IOError as e:
        print(f"File error: {e}", file=sys.stderr)
        return False

def main():
    """
    Main function to run the FTP download from command line arguments.

    5 Test Cases (using public FTP servers):

    Test Case 1: Download readme.txt from test.rebex.net
    python your_script_name.py test.rebex.net demo password /readme.txt rebex_readme.txt

    Test Case 2: Download a test file from ftp.dlptest.com
    python your_script_name.py ftp.dlptest.com dlpuser rNrKYTX9g7z3RgJR /test-file-100kb.txt dlp_test_100kb.txt

    Test Case 3: Download a different file from test.rebex.net
    python your_script_name.py test.rebex.net demo password /pub/example/readme.txt rebex_pub_readme.txt

    Test Case 4: (Dummy) Download a backup file from a private server
    python your_script_name.py my-private-ftp.net admin secretpass /backups/2023.zip backup.zip

    Test Case 5: (Dummy) Download a log file from a local network server
    python your_script_name.py 192.168.1.100 localuser 12345 /logs/app.log app_log_today.log
    """
    if len(sys.argv) < 6:
        print("Usage: python your_script_name.py <hostname> <username> <password> <remote_filepath> <local_filename>", file=sys.stderr)
        sys.exit(1)

    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    remote_file = sys.argv[4]
    local_file = sys.argv[5]

    download_file_from_ftp(hostname, username, password, remote_file, local_file)

if __name__ == "__main__":
    main()