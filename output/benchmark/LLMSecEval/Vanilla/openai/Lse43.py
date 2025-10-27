from pathlib import Path

def read_from_safe(filename: str) -> str:
    try:
        base = Path("/safe").resolve(strict=True)
    except Exception as e:
        return f"ERROR: base directory not available - {e}"
    try:
        target = (base / filename).resolve(strict=True)
        try:
            target.relative_to(base)
        except Exception:
            return "ERROR: Access outside /safe is not allowed"
        return target.read_text(encoding="utf-8")
    except Exception as e:
        return f"ERROR: {e}"

if __name__ == "__main__":
    tests = [
        "example.txt",
        "notes.md",
        "data.json",
        "subdir/file.txt",
        "../etc/passwd"
    ]
    for t in tests:
        print(f"== {t} ==")
        print(read_from_safe(t))
        print()