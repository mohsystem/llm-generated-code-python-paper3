
import ftplib
import sys
import ssl
import os

def download_file(hostname, username, password, remote_file, local_file):
    """\n    Downloads a file from FTP server\n    \n    Args:\n        hostname: FTP server hostname\n        username: FTP username\n        password: FTP password\n        remote_file: Path to remote file on FTP server\n        local_file: Local path where file will be saved\n    \n    Returns:\n        bool: True if successful, False otherwise\n    """
    try:
        # Create FTP_TLS object for secure connection
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ftp = ftplib.FTP_TLS(context=context)
        
        # Connect to FTP server
        ftp.connect(hostname, 21, timeout=30)
        
        # Login
        ftp.login(username, password)
        
        # Secure data connection
        ftp.prot_p()
        
        # Download file
        with open(local_file, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_file}', f.write)
        
        print(f"File downloaded successfully: {local_file}")
        
        # Close connection
        ftp.quit()
        return True
        
    except ftplib.all_errors as e:
        print(f"FTP error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

def main():
    if len(sys.argv) < 5:
        print("Usage: python Task77.py <hostname> <username> <password> <remote_file> [local_file]")
        print("\\nRunning test cases with sample data...\\n")
        
        # Test cases (these will fail without actual FTP server)
        test_cases = [
            ("ftp.example.com", "testuser", "testpass", "/data/file1.txt", "downloaded_file1.txt"),
            ("ftp.test.com", "admin", "admin123", "/sensitive/report.pdf", "report.pdf"),
            ("192.168.1.100", "user1", "password1", "/docs/document.docx", "document.docx"),
            ("ftp.secure.com", "secureuser", "securepass", "/files/data.csv", "data.csv"),
            ("localhost", "localuser", "localpass", "/temp/test.txt", "test.txt")
        ]
        
        for i, (host, user, passwd, remote, local) in enumerate(test_cases, 1):
            print(f"Test Case {i}:")
            download_file(host, user, passwd, remote, local)
            print()
        
        return
    
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    remote_file = sys.argv[4]
    local_file = sys.argv[5] if len(sys.argv) > 5 else os.path.basename(remote_file)
    
    download_file(hostname, username, password, remote_file, local_file)

if __name__ == "__main__":
    main()
