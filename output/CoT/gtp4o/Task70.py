import os
import sys
import stat
import tempfile

MAX_SIZE = 10 * 1024 * 1024  # 10 MB

def read_file(path: str):
    if path is None:
        return None
    try:
        # Normalize path
        norm = os.path.abspath(os.path.normpath(path))

        # Reject symlinks
        if os.path.islink(norm):
            return None

        # Stat without following symlinks to verify regular file and size
        try:
            st = os.stat(norm, follow_symlinks=False)
        except FileNotFoundError:
            return None

        if not stat.S_ISREG(st.st_mode):
            return None
        if not os.access(norm, os.R_OK):
            return None
        if st.st_size > MAX_SIZE:
            return None

        # Stream read to avoid TOCTOU issues; enforce MAX_SIZE while reading
        total = 0
        chunks = []
        with open(norm, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SIZE:
                    return None
                chunks.append(chunk)
        data = b''.join(chunks)
        return data.decode('utf-8', errors='replace')
    except Exception:
        return None

def _make_temp_with_content(content: str):
    f = tempfile.NamedTemporaryFile(prefix="task70_", suffix=".txt", delete=False)
    name = f.name
    try:
        if content is not None:
            f.write(content.encode('utf-8'))
        f.flush()
    finally:
        f.close()
    return name

def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            out = read_file(arg)
            if out is not None:
                sys.stdout.write(out)
                if not out.endswith("\n"):
                    sys.stdout.write("\n")
            else:
                print("ERROR")
    else:
        # 5 test cases
        created = []
        try:
            t1 = _make_temp_with_content("Hello from test 1\n")
            t2 = _make_temp_with_content("Line1\nLine2\nLine3\n")
            t3 = _make_temp_with_content("")  # empty
            t4 = _make_temp_with_content("Unicode: αβγ, emoji: 🙂\n")
            t5 = "this_path_should_not_exist_12345.txt"

            created.extend([t1, t2, t3, t4])

            tests = [t1, t2, t3, t4, t5]
            for i, p in enumerate(tests, 1):
                print(f"Test {i}:")
                res = read_file(p)
                if res is not None:
                    sys.stdout.write(res)
                    if not res.endswith("\n"):
                        sys.stdout.write("\n")
                else:
                    print("ERROR")
        finally:
            for p in created:
                try:
                    os.remove(p)
                except Exception:
                    pass

if __name__ == "__main__":
    main()