import os
import sys
import tempfile
import urllib.request
import urllib.parse
import shutil
import struct
import subprocess

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
EXEC_TIMEOUT = 30

def _is_allowed_host(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in ("google.com", "googleusercontent.com"):
        return True
    if h.endswith(".google.com") or h.endswith(".googleusercontent.com"):
        return True
    if h in ("drive.google.com", "docs.google.com"):
        return True
    return False

def _is_valid_pe(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            if f.seek(0, os.SEEK_END) or f.tell() < 64:
                f.seek(0)
            f.seek(0)
            mz = f.read(2)
            if mz != b"MZ":
                return False
            f.seek(0x3C)
            e_lfanew_bytes = f.read(4)
            if len(e_lfanew_bytes) != 4:
                return False
            (e_lfanew,) = struct.unpack("<I", e_lfanew_bytes)
            if e_lfanew < 0:
                return False
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if e_lfanew + 4 > size:
                return False
            f.seek(e_lfanew)
            sig = f.read(4)
            if sig != b"PE\x00\x00":
                return False
            return True
    except Exception:
        return False

def download_and_execute_exe(url: str) -> int:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return -10  # invalid URL

    if parsed.scheme.lower() != "https":
        return -10  # invalid scheme

    if not _is_allowed_host(parsed.hostname or ""):
        return -11  # disallowed host

    req = urllib.request.Request(url, headers={
        "User-Agent": "Task86/1.0 (+https://example.com)",
        "Accept": "*/*",
    })
    tmp_path = None
    resp = None
    try:
        resp = urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT + READ_TIMEOUT)
        final_url = resp.geturl()
        final_host = urllib.parse.urlparse(final_url).hostname or ""
        if not _is_allowed_host(final_host):
            return -11  # redirected to disallowed host

        # Check content length if provided
        cl = resp.headers.get("Content-Length")
        if cl is not None:
            try:
                if int(cl) > MAX_DOWNLOAD_SIZE:
                    return -13  # too large
            except ValueError:
                pass

        # Stream download
        fd, tmp_path = tempfile.mkstemp(prefix="Task86_", suffix=".exe")
        os.close(fd)
        total = 0
        with open(tmp_path, "wb") as out:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_SIZE:
                    return -13
                out.write(chunk)

        if not _is_valid_pe(tmp_path):
            return -14  # invalid exe

        if os.name.lower() != "nt":
            return -12  # not Windows

        try:
            completed = subprocess.run([tmp_path], shell=False, timeout=EXEC_TIMEOUT)
            return int(completed.returncode)
        except subprocess.TimeoutExpired:
            try:
                # On timeout, ensure process is terminated if started
                pass
            finally:
                return -17
        except PermissionError:
            return -16
        except Exception:
            return -16

    except urllib.error.URLError:
        return -15
    except Exception:
        return -15
    finally:
        try:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

if __name__ == "__main__":
    tests = [
        "https://drive.google.com/uc?export=download&id=FILE_ID_1",
        "https://docs.google.com/uc?export=download&id=FILE_ID_2",
        "http://drive.google.com/uc?export=download&id=FILE_ID_3",
        "https://example.com/file.exe",
        "https://googleusercontent.com/path/to/file.exe",
    ]
    for i, t in enumerate(tests, 1):
        rc = download_and_execute_exe(t)
        print(f"Test {i} exit code: {rc}")