# Task39 - Python
# Chain-of-Through in comments:
# 1) Understand: run a system command to show file content and return it.
# 2) Security: validate filename; avoid shell; ensure regular file.
# 3) Generation: use subprocess with shell=False; use 'cat -- file' on Unix and 'cmd /c type file' on Windows.
# 4) Review: whitelist characters; check file exists; handle exceptions.
# 5) Output: secure final function and 5 test cases.

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_FILENAME_LEN = 4096
SAFE_PATTERN = re.compile(r'^[A-Za-z0-9_./\\ \-:]+$')

def _is_safe_filename(filename: str) -> bool:
    if not isinstance(filename, str):
        return False
    if len(filename) == 0 or len(filename) > MAX_FILENAME_LEN:
        return False
    if '\x00' in filename:
        return False
    if not SAFE_PATTERN.match(filename):
        return False
    if os.name == 'nt':
        # Disallow dangerous cmd metacharacters and quotes
        if any(c in filename for c in '&|><^%!\r\n"\''):
            return False
    return True

def display_file_secure(filename: str) -> str:
    if not _is_safe_filename(filename):
        return "Error: Invalid filename."
    p = Path(filename)
    try:
        if not (p.exists() and p.is_file()):
            return "Error: File not found or not a regular file."
    except Exception:
        return "Error: Access denied."

    if os.name == 'nt':
        cmd = ['cmd.exe', '/c', 'type', filename]
    else:
        cmd = ['/bin/cat', '--', filename]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if res.returncode == 0:
            return res.stdout
        else:
            return f"Error: Command failed with exit code {res.returncode}. Output:\n{res.stdout or res.stderr}"
    except Exception:
        return "Error: Failed to execute command."

def _write_file(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')

def main():
    # Create temp directory and files for testing
    temp_root = Path(tempfile.mkdtemp(prefix="task39-py-"))
    f1 = temp_root / "file1.txt"
    _write_file(f1, "Hello from file1\nLine2\n")

    f2 = temp_root / "file with spaces.txt"
    _write_file(f2, "Content with spaces in filename\n")

    f3 = temp_root / "-leadingDash.txt"
    _write_file(f3, "Filename starts with dash\n")

    f4 = temp_root / "normal-_.txt"
    _write_file(f4, "Normal file name content\n")

    f5 = temp_root / "does_not_exist.txt"

    print("Test1:\n" + display_file_secure(str(f1)))
    print("Test2:\n" + display_file_secure(str(f2)))
    print("Test3:\n" + display_file_secure(str(f3)))
    print("Test4:\n" + display_file_secure(str(f4)))
    print("Test5:\n" + display_file_secure(str(f5)))

if __name__ == "__main__":
    main()