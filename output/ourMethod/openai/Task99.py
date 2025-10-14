import os
import re
from typing import List, TextIO

def find_matching_lines(base_dir: str, rel_path: str) -> List[str]:
    if base_dir is None or rel_path is None:
        raise ValueError("Base directory and path must not be None.")
    if len(rel_path) == 0 or len(rel_path) > 4096:
        raise ValueError("Invalid path length.")
    if os.path.isabs(rel_path):
        raise ValueError("Absolute paths are not allowed.")

    base_dir_real = os.path.abspath(base_dir)
    if not os.path.isdir(base_dir_real):
        raise ValueError("Base directory does not exist or is not a directory.")

    candidate = os.path.normpath(os.path.join(base_dir_real, rel_path))

    common = os.path.commonpath([base_dir_real, candidate])
    if common != base_dir_real:
        raise ValueError("Resolved path escapes the base directory.")

    # lstat to refuse symlinks and ensure regular file
    try:
        st_l = os.lstat(candidate)
    except FileNotFoundError:
        raise ValueError("File does not exist.")

    if os.path.isdir(candidate):
        raise ValueError("Path is a directory, expected a file.")
    if os.path.islink(candidate):
        raise ValueError("Refusing to process symbolic links.")

    # Try to mitigate TOCTOU: open with O_NOFOLLOW if available and verify inode/device
    flags = os.O_RDONLY
    O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    if O_NOFOLLOW:
        flags |= O_NOFOLLOW

    fd = None
    f: TextIO
    try:
        fd = os.open(candidate, flags)
        st_f = os.fstat(fd)
        # Compare inode and device to reduce TOCTOU risks
        if (st_f.st_ino != st_l.st_ino) or (st_f.st_dev != st_l.st_dev):
            raise ValueError("File changed between check and use.")

        f = os.fdopen(fd, mode="r", encoding="utf-8", newline="")
        fd = None  # Ownership transferred to f
        pattern = re.compile(r'^\d.*\.$')

        matches: List[str] = []
        for line in f:
            line = line.rstrip('\n')
            if pattern.match(line):
                matches.append(line)
        return matches
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

def _write_file(path: str, lines: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

def _print_result(title: str, result: List[str]) -> None:
    print(f"=== {title} ===")
    if not result:
        print("(no matches)")
    else:
        for s in result:
            print(s)

if __name__ == "__main__":
    import tempfile
    base = tempfile.mkdtemp(prefix="task99_py_base_")
    _write_file(os.path.join(base, "t1.txt"), [
        "123 start and end.",
        "Nope",
        "9.",
        "0x23.",
        "abc."
    ])
    _write_file(os.path.join(base, "t2.txt"), [
        "A1.",
        "1 but no dot",
        "44.",
        "7!"
    ])
    _write_file(os.path.join(base, "t3.txt"), [
        "...",
        "1a.",
        "",
        "2."
    ])
    os.makedirs(os.path.join(base, "subdir"), exist_ok=True)
    _write_file(os.path.join(base, "subdir", "inner.txt"), [
        "777.",
        "x7."
    ])

    # 5 test cases
    try:
        _print_result("Test1 t1.txt", find_matching_lines(base, "t1.txt"))
    except Exception as e:
        print("Test1 error:", e)

    try:
        _print_result("Test2 t2.txt", find_matching_lines(base, "t2.txt"))
    except Exception as e:
        print("Test2 error:", e)

    try:
        _print_result("Test3 t3.txt", find_matching_lines(base, "t3.txt"))
    except Exception as e:
        print("Test3 error:", e)

    try:
        _print_result("Test4 subdir (directory should be rejected)", find_matching_lines(base, "subdir"))
    except Exception as e:
        print("Test4 error:", e)

    try:
        _print_result("Test5 path traversal (should be rejected)", find_matching_lines(base, "../t1.txt"))
    except Exception as e:
        print("Test5 error:", e)

    try:
        _print_result("Extra nested file", find_matching_lines(base, "subdir/inner.txt"))
    except Exception as e:
        print("Extra error:", e)