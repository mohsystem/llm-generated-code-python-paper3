# Chain-of-Through process:
# 1) Problem understanding: create a secure function that reads a specified file, returns content; main prints it.
# 2) Security requirements: disallow symlinks, ensure regular file, size limit, safe decoding, robust error handling.
# 3) Secure coding generation: use os.stat with follow_symlinks=False, check S_ISREG, enforce max size, chunked read.
# 4) Code review: validate path, exceptions, avoid following symlinks, resource management via with.
# 5) Secure code output: finalized implementation with 5 test cases.

import os
import stat
import sys
import tempfile

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def read_file_secure(path: str) -> str:
    if path is None or not isinstance(path, str) or path.strip() == "":
        raise ValueError("Invalid path")
    p = os.path.normpath(path)

    try:
        st = os.stat(p, follow_symlinks=False)
    except FileNotFoundError:
        raise FileNotFoundError("File does not exist")
    except PermissionError as e:
        raise PermissionError(f"Permission denied: {e}") from e

    if stat.S_ISLNK(st.st_mode):
        raise OSError("Refusing to read symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise OSError("Not a regular file")
    if st.st_size > MAX_FILE_SIZE:
        raise OSError(f"File too large (limit {MAX_FILE_SIZE} bytes)")

    chunks = []
    total = 0
    with open(p, "rb") as f:
        while True:
            buf = f.read(8192)
            if not buf:
                break
            total += len(buf)
            if total > MAX_FILE_SIZE:
                raise OSError("File grew beyond size limit while reading")
            chunks.append(buf)
    data = b"".join(chunks)
    return data.decode("utf-8", errors="replace")


if __name__ == "__main__":
    # If a path is provided by user, read and print it.
    if len(sys.argv) > 1:
        try:
            print(read_file_secure(sys.argv[1]), end="")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)

    # 5 test cases
    try:
        with tempfile.TemporaryDirectory(prefix="task36_tests_py_") as d:
            # Test 1: small file
            t1 = os.path.join(d, "small.txt")
            with open(t1, "w", encoding="utf-8") as f:
                f.write("Hello\nWorld\n")

            # Test 2: empty file
            t2 = os.path.join(d, "empty.txt")
            open(t2, "wb").close()

            # Test 3: unicode content
            t3 = os.path.join(d, "unicode.txt")
            with open(t3, "w", encoding="utf-8") as f:
                f.write("こんにちは\n🙂\n")

            # Test 4: non-existent path
            t4 = os.path.join(d, "missing.txt")  # don't create

            # Test 5: near-limit (1KB)
            t5 = os.path.join(d, "limit.txt")
            with open(t5, "wb") as f:
                f.write(b"A" * 1024)

            tests = [t1, t2, t3, t4, t5]
            for test in tests:
                print(f"\n--- Reading: {test} ---")
                try:
                    print(read_file_secure(test), end="")
                except Exception as e:
                    print(f"Error: {e}")
    except Exception as e:
        print(f"Test setup error: {e}", file=sys.stderr)