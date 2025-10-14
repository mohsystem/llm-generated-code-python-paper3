import os
import sys
import ssl
import socket
from ftplib import FTP, FTP_TLS
from typing import Optional

def _sanitize_filename(name: str) -> str:
    if not name:
        return ""
    allowed = []
    for ch in name:
        if ch.isalnum() or ch in ('.', '_', '-'):
            allowed.append(ch)
        else:
            allowed.append('_')
    result = ''.join(allowed)
    if result in ("", ".", ".."):
        return ""
    return result

def _unique_filename(base: str) -> str:
    if not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    for i in range(1, 10000):
        cand = f"{root}_{i}{ext}"
        if not os.path.exists(cand):
            return cand
    return f"{root}_{int(__import__('time').time())}{ext}"

def download_file(host: str, port: int, username: str, password: str, remote_path: str, use_tls: bool = True, timeout: int = 15) -> Optional[str]:
    ftp = None
    local_path = None
    try:
        basename = os.path.basename(remote_path)
        basename = _sanitize_filename(basename) or "downloaded.bin"
        local_path = _unique_filename(basename)

        if use_tls:
            context = ssl.create_default_context()
            # Enforce certificate verification and hostname checking
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            ftp = FTP_TLS(context=context, timeout=timeout)
        else:
            ftp = FTP(timeout=timeout)

        ftp.connect(host, port)
        if use_tls and isinstance(ftp, FTP_TLS):
            try:
                ftp.auth()  # Upgrade control connection to TLS
            except Exception:
                # Some servers require login before AUTH TLS; proceed anyway
                pass

        ftp.login(username, password)

        if use_tls and isinstance(ftp, FTP_TLS):
            try:
                ftp.prot_p()  # Protect data channel
            except Exception:
                pass

        ftp.voidcmd('TYPE I')  # binary mode
        with open(local_path, 'wb') as f:
            ftp.retrbinary(f"RETR {remote_path}", f.write)

        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

        return local_path
    except Exception:
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
            except Exception:
                pass
        try:
            if ftp:
                ftp.close()
        except Exception:
            pass
        return None

if __name__ == "__main__":
    if len(sys.argv) >= 6:
        host = sys.argv[1]
        try:
            port = int(sys.argv[2])
        except Exception:
            port = 21
        username = sys.argv[3]
        password = sys.argv[4]
        remote_path = sys.argv[5]
        use_tls = True
        if len(sys.argv) >= 7:
            use_tls = sys.argv[6].lower() in ("1", "true", "yes", "y")
        saved = download_file(host, port, username, password, remote_path, use_tls=use_tls, timeout=15)
        if saved:
            print(f"Downloaded to: {saved}")
        else:
            print("Download failed")
    else:
        # 5 test cases (placeholders)
        tests = [
            ("localhost", 21, "user", "pass", "/sensitive.txt", False),
            ("127.0.0.1", 2121, "anonymous", "anonymous@", "/readme.txt", False),
            ("ftp.example.com", 21, "user1", "secret1", "/pub/file1.bin", True),
            ("ftp.example.org", 21, "user2", "secret2", "/data/report.pdf", True),
            ("192.0.2.1", 21, "test", "test", "/tmp/sample.dat", False),
        ]
        for i, t in enumerate(tests, 1):
            try:
                saved = download_file(t[0], t[1], t[2], t[3], t[4], use_tls=t[5], timeout=5)
                print(f"Test {i}: {'Downloaded to ' + saved if saved else 'Failed'}")
            except Exception:
                print(f"Test {i}: Failed")