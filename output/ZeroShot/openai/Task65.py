import os
import sys

MAX_SIZE = 5 * 1024 * 1024  # 5MB

def _is_valid_filename(filename: str) -> bool:
    if filename is None:
        return False
    s = filename.strip()
    if not s or len(s) > 255:
        return False
    if s in (".", ".."):
        return False
    invalid = set('<>:"/\\|?*')
    for ch in s:
        if ord(ch) < 32 or ord(ch) == 127:
            return False
        if ch in invalid:
            return False
    return True

def read_file_secure(filename: str):
    if not _is_valid_filename(filename):
        sys.stderr.write("Invalid filename format.\n")
        return None
    path = os.path.normpath(filename)
    # Since we disallow separators, this should be a simple name in CWD
    try:
        if not os.path.exists(path):
            sys.stderr.write("File does not exist.\n")
            return None
        if not os.path.isfile(path):
            sys.stderr.write("Not a regular file.\n")
            return None
        if not os.access(path, os.R_OK):
            sys.stderr.write("File is not readable.\n")
            return None
        size = os.path.getsize(path)
        if size > MAX_SIZE:
            sys.stderr.write("File too large.\n")
            return None
        with open(path, "rb") as f:
            data = f.read()
        return data.decode("utf-8", errors="strict")
    except Exception as e:
        sys.stderr.write(f"I/O error: {e}\n")
        return None

def _write_sample(name: str, content: str):
    try:
        with open(name, "wb") as f:
            f.write(content.encode("utf-8"))
    except Exception as e:
        sys.stderr.write(f"Failed to write sample file: {e}\n")

def main():
    # Prepare sample resources
    _write_sample("testfile.txt", "Hello from Task65 (Python)!\nThis is a secure read test.\n")
    try:
        os.makedirs("testdir", exist_ok=True)
    except Exception:
        pass

    tests = [
        "testfile.txt",      # valid
        "nonexistent.txt",   # not exist
        "bad|name.txt",      # invalid char
        "../secret.txt",     # traversal attempt (invalid)
        "testdir"            # directory
    ]

    for idx, fname in enumerate(tests, 1):
        print(f"=== Python Test {idx}: {fname} ===")
        data = read_file_secure(fname)
        if data is not None:
            print(f"Content length: {len(data)}")
            print(data)
        else:
            print("Read failed.")

    # If an argument is provided, try to read it
    if len(sys.argv) > 1:
        res = read_file_secure(sys.argv[1])
        if res is not None:
            print("=== Python Arg Read ===")
            print(res)
        else:
            print("Could not read file from argument.")

if __name__ == "__main__":
    main()