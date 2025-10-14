import os
import platform
import subprocess
import tempfile
import shutil

def display_file_secure(filename: str) -> str:
    if not isinstance(filename, str) or not filename.strip():
        return "Error: Invalid filename."
    if '\x00' in filename:
        return "Error: Invalid character in filename."

    try:
        path = os.path.abspath(os.path.normpath(filename))
        if not os.path.exists(path):
            return "Error: File does not exist."
        if not os.path.isfile(path):
            return "Error: Not a regular file."
        if not os.access(path, os.R_OK):
            return "Error: File is not readable."

        cmd = "more" if platform.system().lower().startswith("win") else "cat"
        res = subprocess.run([cmd, path], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            out = res.stdout if res.stdout else res.stderr
            return f"Error: Command failed with exit code {res.returncode}. Output: {out}"
        return res.stdout
    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    # Prepare 5 test cases
    temp_dir = tempfile.mkdtemp(prefix="task39_")
    try:
        f1 = os.path.join(temp_dir, "file1.txt")
        f2 = os.path.join(temp_dir, "file with spaces.txt")
        f3 = os.path.join(temp_dir, "empty.txt")
        invalid = os.path.join(temp_dir, "no_such_file.txt")
        d = os.path.join(temp_dir, "subdir")

        with open(f1, "w", encoding="utf-8") as fh:
            fh.write("Hello from file1\nLine 2\n")
        with open(f2, "w", encoding="utf-8") as fh:
            fh.write("Content with spaces in filename\n")
        open(f3, "w", encoding="utf-8").close()
        os.makedirs(d, exist_ok=True)

        print("Test 1 (regular file):")
        print(display_file_secure(f1))

        print("Test 2 (file with spaces):")
        print(display_file_secure(f2))

        print("Test 3 (empty file):")
        print(display_file_secure(f3))

        print("Test 4 (invalid path):")
        print(display_file_secure(invalid))

        print("Test 5 (directory path):")
        print(display_file_secure(d))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)