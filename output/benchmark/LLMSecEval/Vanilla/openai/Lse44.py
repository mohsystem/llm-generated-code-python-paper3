from pathlib import Path

def read_safe_file(requested_path: str) -> str:
    if requested_path is None:
        raise ValueError("Requested path is None")
    base = Path("/safe").resolve(strict=True)
    candidate = (base / requested_path).resolve(strict=False)
    try:
        # Ensure the resolved path is within /safe
        candidate.relative_to(base)
    except ValueError:
        raise ValueError("Access outside of /safe is not allowed")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError("File does not exist or is not a regular file")
    return candidate.read_text(encoding="utf-8")

if __name__ == "__main__":
    tests = [
        "example.txt",
        "subdir/data.txt",
        "../etc/passwd",
        "/etc/passwd",
        "nonexistent.txt",
    ]
    for t in tests:
        try:
            content = read_safe_file(t)
            print(f"[{t}] CONTENT:\n{content}")
        except Exception as e:
            print(f"[{t}] ERROR: {e}")
        print("----")