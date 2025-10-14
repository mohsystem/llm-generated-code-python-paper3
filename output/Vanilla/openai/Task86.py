import os
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.parse

def download_and_execute(url: str, dest_dir: str | None = None) -> int:
    """
    Downloads an EXE from the given URL to dest_dir (or temp directory if None) and executes it.
    Returns the process exit code, or a negative value on error.
    """
    try:
        if dest_dir is None or not dest_dir.strip():
            dir_path = tempfile.mkdtemp(prefix="dl_exec_py_")
        else:
            dir_path = dest_dir
            os.makedirs(dir_path, exist_ok=True)

        # Derive filename from URL; ensure .exe extension
        try:
            parsed = urllib.parse.urlparse(url)
            name = os.path.basename(parsed.path) or "downloaded_program.exe"
            if not name.lower().endswith(".exe"):
                name += ".exe"
        except Exception:
            name = "downloaded_program.exe"

        target = os.path.join(dir_path, name)

        req = urllib.request.Request(url, headers={"User-Agent": "Task86-Python-Downloader/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(target, "wb") as f:
            shutil.copyfileobj(resp, f)

        # Execute the downloaded EXE
        # Note: This is Windows-specific. On non-Windows OS, this will likely fail.
        completed = subprocess.run([target], shell=False)
        return int(completed.returncode)
    except Exception:
        return -1

if __name__ == "__main__":
    # Five test cases (placeholders). Replace with actual reachable EXE URLs in real use.
    tests = [
        "https://example.com/program1.exe",
        "https://example.com/program2.exe",
        "https://example.org/tools/setup.exe",
        "https://example.net/app/latest.exe",
        "https://example.com/download/myapp.exe",
    ]
    for u in tests:
        rc = download_and_execute(u, None)
        print(f"URL: {u} -> Exit Code: {rc}")