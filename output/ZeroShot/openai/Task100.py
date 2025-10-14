import os
import re
import stat
import sys
import tempfile

MAX_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_PATTERN_LEN = 10000

def search_in_file(pattern: str, file_path: str) -> list:
    if pattern is None or file_path is None:
        raise ValueError("Pattern and file path must not be None.")
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError("Pattern too long.")
    st = os.lstat(file_path)
    if not stat.S_ISREG(st.st_mode):
        raise OSError("Not a regular file.")
    if st.st_size > MAX_BYTES:
        raise OSError("File too large.")
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}") from e
    return rx.findall(content)

def _create_temp_file_with_content(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="task100_", suffix=".txt", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        raise
    return path

def _run_tests():
    content = "The quick brown fox jumps over the lazy dog.\nNumbers: 12345 and 67890.\nTHE end.\n"
    patterns = [
        "fox",
        "[A-Za-z]{4}",
        "[Tt][Hh][Ee]",
        "[0-9]+",
        "notfound",
    ]
    path = None
    try:
        path = _create_temp_file_with_content(content)
        print(f"Test file: {path}")
        for i, p in enumerate(patterns, 1):
            print(f"Test {i} Pattern: {p}")
            try:
                results = search_in_file(p, path)
                print(f"Matches found: {len(results)}")
                for m in results:
                    if isinstance(m, tuple):
                        print("".join(m))
                    else:
                        print(m)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
            print("---")
    finally:
        if path:
            try:
                os.remove(path)
            except Exception:
                pass

def main():
    if len(sys.argv) == 3:
        try:
            matches = search_in_file(sys.argv[1], sys.argv[2])
            print(f"Matches found: {len(matches)}")
            for m in matches:
                if isinstance(m, tuple):
                    print("".join(m))
                else:
                    print(m)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        _run_tests()

if __name__ == "__main__":
    main()