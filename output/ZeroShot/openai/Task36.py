import os
import sys
import tempfile

def read_file_and_print(file_path: str) -> str:
    """
    Reads a file at file_path, prints its contents to the console, and returns the contents as a string.
    Enforces a maximum size of 10 MB and avoids following symlinks.
    """
    MAX_BYTES = 10 * 1024 * 1024  # 10 MB

    if not isinstance(file_path, str) or not file_path.strip():
        print("Error: file path is invalid.", file=sys.stderr)
        return ""

    try:
        # Avoid following symlinks
        if not os.path.exists(file_path):
            print("Error: file does not exist.", file=sys.stderr)
            return ""
        if os.path.islink(file_path):
            print("Error: symlinks are not allowed.", file=sys.stderr)
            return ""
        st = os.stat(file_path, follow_symlinks=False)
        if not os.path.isfile(file_path):
            print("Error: not a regular file.", file=sys.stderr)
            return ""
        if not os.access(file_path, os.R_OK):
            print("Error: file is not readable.", file=sys.stderr)
            return ""
    except OSError:
        print("Error: unable to access file metadata.", file=sys.stderr)
        return ""

    parts = []
    total = 0
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    print("Error: file exceeds maximum allowed size of 10 MB.", file=sys.stderr)
                    return ""
                # Decode as UTF-8, replacing invalid bytes to avoid exceptions
                parts.append(chunk.decode('utf-8', errors='replace'))
    except (OSError, IOError):
        print("Error: I/O error while reading the file.", file=sys.stderr)
        return ""

    out = "".join(parts)
    print(out, end="")
    return out

if __name__ == "__main__":
    # Create 4 temp files and 1 non-existent path for testing
    tmp_files = []
    contents = [
        "Hello, Task36!\n",
        "",  # empty
        "こんにちは世界\nEmoji: 😀\n",
        "Line1\nLine2\nLine3\n"
    ]

    paths = []
    for text in contents:
        f = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, prefix="task36_", suffix=".txt")
        f.write(text)
        f.close()
        paths.append(f.name)
        tmp_files.append(f.name)

    non_existent = os.path.join(tempfile.gettempdir(), f"does_not_exist_{os.getpid()}_{os.urandom(4).hex()}.txt")
    paths.append(non_existent)

    # Run 5 test cases
    for p in paths:
        read_file_and_print(p)

    # Cleanup temp files (optional)
    for p in tmp_files:
        try:
            os.remove(p)
        except OSError:
            pass