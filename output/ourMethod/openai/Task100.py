import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB
MAX_PATTERN_LENGTH = 10000
MAX_MATCHES = 10000

def _path_has_symlink(p: Path) -> bool:
    try:
        parts = p.parts
        if not parts:
            return False
        accum = Path(parts[0])
        for part in parts[1:]:
            if accum.is_symlink():
                return True
            accum = accum / part
        # Check final path as well
        return p.is_symlink()
    except Exception:
        return True

def search_file(pattern: str, file_path: str) -> List[str]:
    if not isinstance(pattern, str) or not isinstance(file_path, str):
        raise ValueError("Invalid input types")
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError("Invalid pattern length")

    base_dir = Path.cwd().resolve()
    target = Path(file_path)
    # Normalize path without following symlinks yet
    abs_target = (base_dir / target).resolve(strict=False)

    # Ensure within base directory
    try:
        abs_norm = abs_target
        if base_dir not in abs_norm.parents and abs_norm != base_dir:
            raise ValueError("Path escapes base directory")
    except Exception as e:
        raise ValueError("Invalid path") from e

    # Reject symlinks
    if _path_has_symlink(abs_target):
        raise ValueError("Symbolic links are not allowed")

    # Ensure regular file
    try:
        st = os.stat(abs_target, follow_symlinks=False)
        if not os.path.isfile(abs_target) or not stat_is_regular(st.st_mode):
            raise ValueError("Not a regular file")
    except FileNotFoundError:
        raise ValueError("File not found")
    except Exception as e:
        raise ValueError(f"Stat error: {e}")

    # Size check
    if st.st_size < 0 or st.st_size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    # Read and search
    try:
        with open(abs_target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        raise ValueError(f"Read error: {e}")

    try:
        regex = re.compile(pattern, re.DOTALL)
    except re.error as e:
        raise ValueError(f"Invalid regex: {e}")

    results: List[str] = []
    count = 0
    pos = 0
    while True:
        m = regex.search(content, pos)
        if not m:
            break
        results.append(m.group(0))
        count += 1
        if count >= MAX_MATCHES:
            break
        # Avoid zero-length match infinite loop
        next_pos = m.end()
        if next_pos == pos:
            next_pos += 1
        pos = next_pos
        if pos > len(content):
            break
    return results

def stat_is_regular(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000

def create_file(name: str, content: str) -> None:
    base_dir = Path.cwd().resolve()
    p = (base_dir / name).resolve(strict=False)
    if base_dir not in p.parents and p != base_dir:
        raise ValueError("Refusing to create outside base directory")
    # Best-effort secure creation
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(p, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="strict") as f:
            f.write(content)
    except FileExistsError:
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)

def print_results(results: List[str]) -> None:
    print(f"Matches: {len(results)}")
    for i, s in enumerate(results):
        safe = s.replace("\r", "\\r").replace("\n", "\\n")
        if len(safe) > 200:
            safe = safe[:200] + "..."
        print(f"[{i}] {safe}")

def main() -> None:
    if len(sys.argv) == 3:
        try:
            res = search_file(sys.argv[1], sys.argv[2])
            print_results(res)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
        return

    # 5 test cases
    try:
        create_file("py_test1.txt", "Hello world!\nThis is a test file.")
        create_file("py_test2.txt", "Numbers: 123 456 789\nEnd.")
        create_file("py_test3.txt", "First line.\nSecond line.\nThird line.")
        create_file("py_test4.txt", "Contacts: alice@example.com, bob@test.com")
        create_file("py_test5.txt", "No matching tokens here.")

        r1 = search_file("world", "py_test1.txt")
        print("Test1: pattern='world' file='py_test1.txt'")
        print_results(r1)

        r2 = search_file(r"\d+", "py_test2.txt")
        print("Test2: pattern='\\d+' file='py_test2.txt'")
        print_results(r2)

        r3 = search_file(r"Second line\.", "py_test3.txt")
        print("Test3: pattern='Second line\\.' file='py_test3.txt'")
        print_results(r3)

        r4 = search_file(r"[A-Za-z]+@[A-Za-z]+\.com", "py_test4.txt")
        print("Test4: pattern='[A-Za-z]+@[A-Za-z]+\\.com' file='py_test4.txt'")
        print_results(r4)

        r5 = search_file("XYZ", "py_test5.txt")
        print("Test5: pattern='XYZ' file='py_test5.txt'")
        print_results(r5)
    except Exception as e:
        print(f"Test error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()