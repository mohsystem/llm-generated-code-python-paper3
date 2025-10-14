import os
import sys
import stat
import subprocess
from pathlib import Path
import re
from typing import List


def _is_windows() -> bool:
    return os.name == "nt"


def _safe_chars(s: str) -> bool:
    # Allow only safe characters; refuse spaces and shell metacharacters
    return bool(re.fullmatch(r"[A-Za-z0-9._/\-\\]{1,255}", s))


def _validate_and_resolve(base_dir: str, user_input: str) -> Path:
    if user_input is None:
        raise ValueError("Invalid input: None")
    if "\x00" in user_input:
        raise ValueError("Invalid input: null byte")
    if not _safe_chars(user_input):
        raise ValueError("Invalid filename: characters or length")
    upath = Path(user_input)
    if upath.is_absolute():
        raise ValueError("Path must be relative")

    base_real = Path(base_dir).resolve(strict=True)
    candidate = (base_real / upath)
    # Lexical normalization without resolving symlinks
    candidate = Path(os.path.normpath(str(candidate)))

    # Ensure inside base lexically
    try:
        _ = candidate.relative_to(base_real)
    except Exception:
        raise ValueError("Path traversal detected")

    # Disallow any symlink in the path (including intermediates)
    cur = base_real
    rel_parts = list(candidate.relative_to(base_real).parts)
    for part in rel_parts:
        cur = cur / part
        if cur.exists() and os.path.islink(cur):
            raise ValueError(f"Symlink not allowed: {cur}")

    # Must exist and be a regular file (no symlink)
    if not candidate.exists():
        raise FileNotFoundError("File does not exist")
    st = os.stat(candidate, follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("Not a regular file")

    return candidate


def display_file_using_command(base_dir: str, user_input: str) -> str:
    try:
        # Ensure base exists
        Path(base_dir).mkdir(parents=True, exist_ok=True)
        path = _validate_and_resolve(base_dir, user_input)
        if _is_windows():
            cmd: List[str] = ["more", str(path)]
        else:
            cmd = ["cat", str(path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if proc.returncode != 0 and not proc.stdout:
            return f"ERROR: Command failed with exit code {proc.returncode}: {proc.stderr.strip()}"
        return proc.stdout
    except Exception as e:
        return f"ERROR: {e}"


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> None:
    base = "safe_base_dir_task39_py"
    base_path = Path(base).resolve()
    base_path.mkdir(parents=True, exist_ok=True)

    # Prepare test files
    _write_file(base_path / "file1.txt", "Hello from Python file1\nLine2\n")
    (base_path / "subdir").mkdir(parents=True, exist_ok=True)
    _write_file(base_path / "subdir" / "file2.txt", "Hello from Python subdir file2\n")
    (base_path / "emptydir").mkdir(parents=True, exist_ok=True)

    tests = [
        "file1.txt",
        "subdir/file2.txt",
        "../outside.txt",
        "nonexistent.txt",
        "subdir",
    ]

    for i, t in enumerate(tests, 1):
        print(f"=== Test {i}: {t} ===")
        out = display_file_using_command(base, t)
        print(out, end="")

if __name__ == "__main__":
    main()