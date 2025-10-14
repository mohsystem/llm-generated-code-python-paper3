import sys
import tempfile
import os

def read_file(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def main():
    args = sys.argv[1:]
    if args:
        for path in args:
            try:
                content = read_file(path)
                sys.stdout.write(content)
                if not content.endswith('\n'):
                    sys.stdout.write('\n')
            except Exception as e:
                print(f"ERROR reading {path}: {e}", file=sys.stderr)
        return

    # 5 test cases using temporary files if no command-line args provided
    files = []
    try:
        for i in range(1, 6):
            fd, p = tempfile.mkstemp(prefix=f"task70_test_{i}_", suffix=".txt")
            os.close(fd)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(f"Test case {i} content.\n")
            files.append(p)
        for p in files:
            sys.stdout.write(read_file(p))
    finally:
        for p in files:
            try:
                os.unlink(p)
            except OSError:
                pass

if __name__ == "__main__":
    main()