
import ftplib
import sys
import os

def download_file(hostname, username, password, remote_file_path, local_file_path):
    try:
        # Create FTP client
        ftp = ftplib.FTP()
        
        # Connect to FTP server
        ftp.connect(hostname)
        print(f"Connected to {hostname}")
        
        # Login to FTP server
        ftp.login(username, password)
        print(f"Logged in as {username}")
        
        # Download file
        with open(local_file_path, 'wb') as local_file:
            ftp.retrbinary('RETR ' + remote_file_path, local_file.write)
        
        print(f"File downloaded successfully: {local_file_path}")
        
        # Close connection
        ftp.quit()
        return True
        
    except ftplib.all_errors as e:
        print(f"FTP error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    if len(sys.argv) < 4:
        print("Usage: python Task77.py <hostname> <username> <password> <remote_file_path>")
        print("\\nRunning test cases with dummy data...\\n")
        
        # Test cases with dummy data (these will fail without actual FTP server)
        print("Test Case 1:")
        download_file("ftp.example.com", "user1", "pass1", "/files/data.txt", "data1.txt")
        
        print("\\nTest Case 2:")
        download_file("ftp.test.com", "admin", "admin123", "/documents/report.pdf", "report2.pdf")
        
        print("\\nTest Case 3:")
        download_file("192.168.1.100", "ftpuser", "ftppass", "/backup/backup.zip", "backup3.zip")
        
        print("\\nTest Case 4:")
        download_file("ftp.server.org", "guest", "guest", "/public/readme.txt", "readme4.txt")
        
        print("\\nTest Case 5:")
        download_file("ftp.demo.net", "testuser", "test@123", "/files/config.xml", "config5.xml")
    else:
        hostname = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        remote_file = sys.argv[4] if len(sys.argv) > 4 else "/data.txt"
        local_file = os.path.basename(remote_file)
        
        download_file(hostname, username, password, remote_file, local_file)

if __name__ == "__main__":
    main()
