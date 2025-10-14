import os
import tempfile
from pathlib import Path
from typing import Optional


def create_executable_script(base_directory: str, filename: str) -> bool:
    if not base_directory or not filename:
        return False

    # Reject path traversal or path separators in filename
    if ".." in filename or "/" in filename or "\\" in filename:
        return False

    try:
        base_path = Path(base_directory).resolve()
        file_path = (base_path / filename).resolve()

        # Ensure the resolved path is inside base_directory
        if not str(file_path).startswith(str(base_path)):
            return False

        # If the destination exists, ensure it's a regular file and not a symlink
        if file_path.exists():
            if not file_path.is_file() or file_path.is_symlink():
                return False

        fd, temp_path = tempfile.mkstemp(suffix=".sh", dir=base_path, text=False)
        try:
            os.write(fd, b"#!/bin/bash\n")
            os.close(fd)

            os.chmod(temp_path, 0o755)

            os.replace(temp_path, str(file_path))

            return True
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            try:
                os.unlink(temp_path)
            except Exception:
                pass
            raise
    except (OSError, ValueError):
        return False


def main() -> None:
    test_dir = tempfile.gettempdir()

    print(f"Test 1 (valid): {create_executable_script(test_dir, 'script.sh')}")
    print(f"Test 2 (valid different name): {create_executable_script(test_dir, 'test_script.sh')}")
    print(f"Test 3 (path traversal attempt): {create_executable_script(test_dir, '../script.sh')}")
    print(f"Test 4 (null filename): {create_executable_script(test_dir, '')}")
    print(f"Test 5 (invalid char): {create_executable_script(test_dir, 'dir/script.sh')}")


if __name__ == "__main__":
    main()
