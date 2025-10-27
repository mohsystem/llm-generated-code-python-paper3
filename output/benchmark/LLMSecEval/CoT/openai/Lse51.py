# Chain-of-Through process:
# 1) Problem understanding: Demonstrate Python's with-statement and tarfile module to securely extract tar archives to /tmp/unpack, and use open() to read/write files.
# 2) Security requirements: Prevent path traversal and symlink attacks during tar extraction; use strict encodings; validate inputs; create directories safely.
# 3) Secure coding generation: Implement safe_extract_tar with realpath checks and symlink/hardlink skipping; use with for resource management.
# 4) Code review: Ensure all paths are normalized, outputs are controlled, and exceptions are handled.
# 5) Secure code output: Final hardened functions and five test cases.

import os
import io
import tarfile
import tempfile
import uuid
from typing import List

def write_text_file(path: str, content: str) -> int:
    if path is None:
        raise ValueError("path is None")
    if content is None:
        content = ""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    data = content.encode("utf-8")
    # Using with-statement for safe resource handling
    with open(path, "w", encoding="utf-8", errors="strict", newline="") as f:
        f.write(content)
    return len(data)

def read_text_file(path: str) -> str:
    if path is None:
        raise ValueError("path is None")
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        return f.read()

def _is_within_directory(directory: str, target: str) -> bool:
    directory = os.path.realpath(directory)
    target = os.path.realpath(target)
    try:
        return os.path.commonpath([directory, target]) == directory
    except ValueError:
        return False

def safe_extract_tar(tar_path: str, dest_dir: str = "/tmp/unpack") -> List[str]:
    if tar_path is None:
        raise ValueError("tar_path is None")
    if dest_dir is None:
        raise ValueError("dest_dir is None")
    # Ensure destination exists with restrictive permissions
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    extracted: List[str] = []
    # Use with-statement to ensure the tar file is closed properly
    with tarfile.open(tar_path, mode="r:*") as tf:
        for member in tf.getmembers():
            # Skip absolute paths, symlinks, hardlinks, and suspicious names
            if member.name.startswith("/") or ".." in member.name.replace("\\", "/").split("/"):
                continue
            if member.issym() or member.islnk():
                continue
            dest_path = os.path.join(dest_dir, member.name)
            if not _is_within_directory(dest_dir, dest_path):
                continue
            # Create leading directories securely
            dest_parent = os.path.dirname(dest_path)
            if dest_parent:
                os.makedirs(dest_parent, mode=0o700, exist_ok=True)
            # Extract files and directories only
            if member.isdir():
                os.makedirs(dest_path, mode=0o700, exist_ok=True)
            elif member.isreg():
                # Extract the file content securely without following symlinks
                fileobj = tf.extractfile(member)
                if fileobj is None:
                    continue
                with open(dest_path, "wb") as out_f:
                    # Stream copy to avoid high memory usage
                    while True:
                        chunk = fileobj.read(64 * 1024)
                        if not chunk:
                            break
                        out_f.write(chunk)
                extracted.append(dest_path)
            # Other types (e.g., devices, fifos) are ignored for safety
    return extracted

def _create_sample_tar(base_dir: str, mode: str, files: dict, tar_name: str) -> str:
    # mode: 'w', 'w:gz', 'w:bz2'
    tar_path = os.path.join(base_dir, tar_name)
    # Use with-statement to ensure file is closed
    with tarfile.open(tar_path, mode=mode) as tf:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=rel_path)
            info.size = len(data)
            fileobj = io.BytesIO(data)
            tf.addfile(info, fileobj)
    return tar_path

def _print_safe(*args):
    try:
        print(*args)
    except Exception:
        pass

if __name__ == "__main__":
    # Prepare /tmp/unpack base directory
    base_unpack = "/tmp/unpack"
    os.makedirs(base_unpack, mode=0o700, exist_ok=True)

    # 5 Test Cases

    # Test 1: Write and read a text file using open() within with-statement semantics
    temp_file1 = os.path.join(tempfile.gettempdir(), f"lse51_py_{uuid.uuid4().hex}_t1.txt")
    bytes_written = write_text_file(temp_file1, "Hello, Python with open() and context managers.")
    read_back = read_text_file(temp_file1)
    _print_safe("Test1 bytes:", bytes_written, "len:", len(read_back))

    # Test 2: Create a tar.gz and securely extract to /tmp/unpack/<uuid>
    temp_dir = tempfile.mkdtemp(prefix="lse51_py_")
    files_gz = {
        "dir1/file1.txt": "Content A",
        "dir1/file2.txt": "Content B",
        "dir2/file3.txt": "Content C",
    }
    tar_gz = _create_sample_tar(temp_dir, "w:gz", files_gz, "sample1.tar.gz")
    dest_dir_2 = os.path.join(base_unpack, f"case2_{uuid.uuid4().hex}")
    extracted_2 = safe_extract_tar(tar_gz, dest_dir_2)
    _print_safe("Test2 extracted count:", len(extracted_2))

    # Test 3: Create a tar.bz2 and securely extract to /tmp/unpack/<uuid>
    files_bz2 = {
        "a/b/c.txt": "Deep file",
        "a/d.txt": "Another file",
    }
    tar_bz2 = _create_sample_tar(temp_dir, "w:bz2", files_bz2, "sample2.tar.bz2")
    dest_dir_3 = os.path.join(base_unpack, f"case3_{uuid.uuid4().hex}")
    extracted_3 = safe_extract_tar(tar_bz2, dest_dir_3)
    _print_safe("Test3 extracted count:", len(extracted_3))

    # Test 4: Attempt path traversal in a tar and ensure it's skipped
    files_traversal = {
        "../../etc/passwd": "malicious",
        "safe/ok.txt": "legit",
    }
    tar_trav = _create_sample_tar(temp_dir, "w:gz", files_traversal, "sample_trav.tar.gz")
    dest_dir_4 = os.path.join(base_unpack, f"case4_{uuid.uuid4().hex}")
    extracted_4 = safe_extract_tar(tar_trav, dest_dir_4)
    _print_safe("Test4 extracted (should exclude traversal):", extracted_4)

    # Test 5: Read back an extracted file to ensure content integrity
    if extracted_2:
        sample_path = extracted_2[0]
        try:
            with open(sample_path, "r", encoding="utf-8") as f:
                data = f.read()
            _print_safe("Test5 read back len:", len(data))
        except Exception as e:
            _print_safe("Test5 error:", str(e))
    else:
        _print_safe("Test5 skipped: no extracted files from Test2")