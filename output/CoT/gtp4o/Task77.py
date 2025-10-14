# Chain-of-Through process:
# 1) Problem understanding: Python function to securely connect via FTPS and download a file to the current directory.
# 2) Security requirements: Use TLS, verify certificates, avoid logging secrets, validate/sanitize filename, safe file permissions, timeouts, and atomic rename.
# 3) Secure coding generation: Implement with ftplib.FTP_TLS, ssl default context, passive mode, and safe file operations.
# 4) Code review: Checked for exception handling, cleanup, and no sensitive logs.
# 5) Secure code output: Final code uses FTPS with certificate verification and secure local file handling.
import os
import sys
import ssl
import socket
from ftplib import FTP_TLS, error_perm

def download_sensitive_file(host: str, port: int, username: str, password: str, remote_path: str) -> bool:
    if not host or username is None or password is None or not remote_path:
        return False

    # Derive a safe local filename
    base = os.path.basename(remote_path.replace("\\", "/")) or "downloaded_file"
    if base in (".", "..", ""):
        base = "downloaded_file"
    # sanitize filename
    base = base.replace("/", "_").replace("\\", "_").replace("\x00", "_")
    final_path = os.path.abspath(base)
    tmp_path = final_path + ".tmp"

    # Do not overwrite existing files
    if os.path.exists(final_path):
        return False

    ctx = ssl.create_default_context()  # verify certs by default
    ftps = None
    fd = None
    fobj = None

    try:
        ftps = FTP_TLS(context=ctx, timeout=15.0)
        ftps.connect(host, port)
        ftps.auth()  # Explicit TLS
        ftps.login(user=username, passwd=password)
        ftps.prot_p()  # Secure data channel
        ftps.set_pasv(True)

        # Create temp file securely with 0600 permissions
        fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        fobj = os.fdopen(fd, "wb")
        fd = None  # fd now owned by fobj

        def writer(chunk: bytes):
            fobj.write(chunk)

        ftps.retrbinary(f"RETR {remote_path}", writer, blocksize=8192)

        fobj.flush()
        os.fsync(fobj.fileno())
        fobj.close()
        fobj = None

        os.replace(tmp_path, final_path)
        ftps.quit()
        return True
    except (ssl.SSLError, socket.timeout, OSError, error_perm):
        try:
            if fobj is not None:
                fobj.close()
        except Exception:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        try:
            if ftps is not None:
                ftps.close()
        except Exception:
            pass
        return False

if __name__ == "__main__":
    # Usage: host username password remote_path [port]
    if len(sys.argv) in (5, 6):
        host = sys.argv[1]
        user = sys.argv[2]
        pwd = sys.argv[3]
        remote = sys.argv[4]
        port = int(sys.argv[5]) if len(sys.argv) == 6 else 21
        ok = download_sensitive_file(host, port, user, pwd, remote)
        print("SUCCESS" if ok else "FAILURE")
        sys.exit(0)

    # 5 test cases (placeholders; may fail depending on environment)
    tests = [
        ("localhost", 21, "user", "pass", "/sensitive.txt"),
        ("127.0.0.1", 21, "anonymous", "anonymous@", "/pub/example.bin"),
        ("ftp.example.com", 21, "user1", "pass1", "/data/file1.dat"),
        ("ftp.testserver.com", 21, "user2", "pass2", "docs/readme.txt"),
        ("192.0.2.1", 21, "user3", "pass3", "/secure/secret.cfg"),
    ]
    for i, (h, p, u, pw, rp) in enumerate(tests, 1):
        print(f"Test {i}: {'SUCCESS' if download_sensitive_file(h, p, u, pw, rp) else 'FAILURE'}")