import os

def read_from_safe_dir(filename: str) -> str:
    if not isinstance(filename, str) or not filename or '\x00' in filename:
        raise ValueError("Invalid filename")

    base = os.path.realpath("/safe")
    if not os.path.isdir(base):
        raise FileNotFoundError("Safe directory not found")

    if os.path.isabs(filename):
        raise PermissionError("Absolute paths are not allowed")

    target = os.path.normpath(os.path.join(base, filename))

    # Ensure target is inside base
    base_with_sep = base if base.endswith(os.sep) else base + os.sep
    target_real_parent = os.path.realpath(os.path.dirname(target))
    if not (target.startswith(base_with_sep) or target == base):
        raise PermissionError("Path escapes safe directory")
    if not target_real_parent.startswith(base_with_sep) and target_real_parent != base:
        raise PermissionError("Resolved parent escapes safe directory")

    # Disallow symlinks in every segment including the final file
    current = base
    rel = os.path.relpath(target, base)
    if rel == os.curdir:
        raise PermissionError("Invalid target")
    for segment in rel.split(os.sep):
        current = os.path.join(current, segment)
        if os.path.islink(current):
            raise PermissionError("Symlinks are not allowed in path")

    if not os.path.isfile(target):
        raise FileNotFoundError("Not a regular file")

    max_bytes = 10 * 1024 * 1024  # 10 MB
    size = os.path.getsize(target)
    if size > max_bytes:
        raise IOError("File too large")

    with open(target, "r", encoding="utf-8", errors="strict") as f:
        return f.read()


if __name__ == "__main__":
    tests = [
        "example.txt",
        "../etc/passwd",
        "/etc/passwd",
        "subdir/notes.txt",
        "symlink_to_secret",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} ({t}):")
        try:
            content = read_from_safe_dir(t)
            preview = (content[:200] + "...") if len(content) > 200 else content
            print(preview)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")
        print()