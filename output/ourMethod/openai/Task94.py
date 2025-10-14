from __future__ import annotations
import os
import io
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple

MAX_LINE_LENGTH = 8192
MAX_REL_PATH_LENGTH = 4096

def _validate_and_resolve_path(base_dir: str, relative_path: str) -> Path:
    if base_dir is None or relative_path is None:
        raise ValueError("Base directory and relative path must not be None.")
    base = Path(base_dir)
    if not base.exists() or not base.is_dir():
        raise OSError("Base directory does not exist or is not a directory.")
    # base must not be a symlink
    try:
        if base.is_symlink():
            raise OSError("Base directory must not be a symbolic link.")
    except Exception:
        # If unsupported, best-effort check via lstat
        st = os.lstat(str(base))
        if os.path.S_ISLNK(st.st_mode):
            raise OSError("Base directory must not be a symbolic link.")

    if not isinstance(relative_path, str) or len(relative_path) == 0 or len(relative_path) > MAX_REL_PATH_LENGTH:
        raise OSError("Invalid relative path length.")
    if "\x00" in relative_path:
        raise OSError("Invalid character in path.")
    rel = Path(relative_path)
    if rel.is_absolute():
        raise OSError("Relative path must not be absolute.")
    for part in rel.parts:
        if part == "..":
            raise OSError("Path traversal detected.")

    # Walk each component and reject symlinks
    cur = base.resolve(strict=True)
    for part in rel.parts:
        if part == ".":
            continue
        cur = cur / part
        try:
            st = os.lstat(str(cur))
            if os.path.S_ISLNK(st.st_mode):
                raise OSError("Symlink encountered in path.")
        except FileNotFoundError:
            # Not created yet; we only need to read existing file, so error out if final not exists later
            pass

    # Final path
    final_path = (base / rel).resolve(strict=False)
    # Ensure final path is inside base
    try:
        base_real = base.resolve(strict=True)
        if base_real not in final_path.parents and final_path != base_real:
            raise OSError("Resolved path escapes base directory.")
    except RuntimeError:
        # On some systems, parents may fail; fallback conservative
        if not str(final_path).startswith(str(base_real) + os.sep):
            raise OSError("Resolved path escapes base directory.")

    # Final must be a regular file and not a symlink
    try:
        st_final = os.lstat(str(final_path))
    except FileNotFoundError:
        raise OSError("Target file does not exist.")
    if os.path.S_ISLNK(st_final.st_mode):
        raise OSError("Target file must not be a symbolic link.")
    if not os.path.S_ISREG(st_final.st_mode):
        raise OSError("Target must be a regular file.")
    return final_path


def read_and_sort_key_value_file(base_dir: str, relative_path: str, delimiter: str) -> List[Tuple[str, str]]:
    if not isinstance(delimiter, str) or len(delimiter) != 1 or delimiter in "\r\n":
        raise ValueError("Invalid delimiter.")
    path = _validate_and_resolve_path(base_dir, relative_path)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    entries: List[Tuple[str, str]] = []
    fd = None
    try:
        fd = os.open(str(path), flags)
        with io.open(fd, mode="r", encoding="utf-8", newline="") as f:
            # fd is consumed by io.open; prevent double-close
            fd = None
            first_line = True
            for raw_line in f:
                if len(raw_line) > MAX_LINE_LENGTH:
                    raise OSError("Line too long.")
                line = raw_line
                if first_line and line.startswith("\ufeff"):
                    line = line.lstrip("\ufeff")
                    first_line = False
                if not first_line:
                    pass
                first_line = False
                trimmed = line.strip()
                if not trimmed or trimmed.startswith("#"):
                    continue
                idx = trimmed.find(delimiter)
                if idx < 0:
                    continue
                key = trimmed[:idx].strip()
                value = trimmed[idx + 1:].strip()
                if not key:
                    continue
                entries.append((key, value))
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

    entries.sort(key=lambda kv: (kv[0], kv[1]))
    return entries


def _write_file(base: Path, rel: str, content: str) -> None:
    # Create directories if needed
    target = base / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    # Use exclusive creation to avoid races
    with open(target, "x", encoding="utf-8", newline="") as f:
        f.write(content)


def _print_result(title: str, entries: List[Tuple[str, str]]) -> None:
    print(title)
    for k, v in entries:
        print(f"{k}={v}")
    print("---")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="kv_safe_base_") as td:
        base = Path(td)
        _write_file(base, "t1.txt", "apple=3\nbanana=1\ncherry=2\n")
        _write_file(base, "t2.txt", "# comment\norange = 10\n banana = 5\nbanana = 2\n")
        (base / "dir" / "sub").mkdir(parents=True, exist_ok=True)
        _write_file(base, "dir/sub/t3.txt", "z=last\n a=first\nm=mid\n")
        _write_file(base, "t4.txt", "x=a=b=c\nn=:emptyBefore\n:badline\n")
        _write_file(base, "t5.txt", "key with spaces = value with spaces\nalpha= \n gamma=3\n")

        r1 = read_and_sort_key_value_file(str(base), "t1.txt", "=")
        r2 = read_and_sort_key_value_file(str(base), "t2.txt", "=")
        r3 = read_and_sort_key_value_file(str(base), "dir/sub/t3.txt", "=")
        r4 = read_and_sort_key_value_file(str(base), "t4.txt", "=")
        r5 = read_and_sort_key_value_file(str(base), "t5.txt", "=")

        _print_result("Test 1:", r1)
        _print_result("Test 2:", r2)
        _print_result("Test 3:", r3)
        _print_result("Test 4:", r4)
        _print_result("Test 5:", r5)


if __name__ == "__main__":
    main()