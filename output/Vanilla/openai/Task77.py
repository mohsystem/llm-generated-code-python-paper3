import os
import sys
from ftplib import FTP, error_perm

def download_ftp_file(host: str, port: int, username: str, password: str, remote_path: str) -> str | None:
    local_name = os.path.basename(remote_path)
    ftp = FTP()
    try:
        ftp.connect(host, port, timeout=30)
        ftp.login(username, password)
        with open(local_name, "wb") as f:
            ftp.retrbinary(f"RETR {remote_path}", f.write)
        ftp.quit()
        return local_name
    except (OSError, error_perm):
        try:
            ftp.close()
        except Exception:
            pass
        return None

if __name__ == "__main__":
    if len(sys.argv) >= 5:
        host = sys.argv[1]
        user = sys.argv[2]
        passwd = sys.argv[3]
        remote = sys.argv[4]
        port = int(sys.argv[5]) if len(sys.argv) >= 6 else 21
        saved = download_ftp_file(host, port, user, passwd, remote)
        print(f"Downloaded: {saved}" if saved else "Download failed")
    else:
        # 5 test cases with public test FTP server
        host = "test.rebex.net"
        user = "demo"
        passwd = "password"
        port = 21
        files = [
            "pub/example/readme.txt",
            "pub/example/ConsoleClient.png",
            "pub/example/KeyGenerator.png",
            "pub/example/WinFormClient.png",
            "pub/example/WinSshShell.png",
        ]
        for f in files:
            saved = download_ftp_file(host, port, user, passwd, f)
            print(f"{'Downloaded' if saved else 'Failed'}: {f}")