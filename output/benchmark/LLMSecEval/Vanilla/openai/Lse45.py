from pathlib import Path

class Lse45:
    @staticmethod
    def read_file_from_safe_dir(safe_dir: str, requested_path: str):
        try:
            base = Path(safe_dir).resolve()
            base.mkdir(parents=True, exist_ok=True)
            req = Path(requested_path)
            if req.is_absolute():
                return None
            candidate = (base / req).resolve(strict=False)
            if candidate == base or base not in candidate.parents:
                return None
            if not candidate.exists() or not candidate.is_file():
                return None
            return candidate.read_text(encoding="utf-8")
        except Exception:
            return None

if __name__ == "__main__":
    base = Path("safe_dir_py").resolve()
    (base / "sub").mkdir(parents=True, exist_ok=True)
    (base / "hello.txt").write_text("Hello from Python", encoding="utf-8")
    (base / "sub" / "inner.txt").write_text("Inner from Python", encoding="utf-8")

    tests = [
        "hello.txt",                      # valid
        "sub/inner.txt",                  # valid in subdir
        "../hello.txt",                   # traversal attempt
        str((base / "hello.txt")),        # absolute path attempt
        "missing.txt"                     # non-existent
    ]

    for t in tests:
        content = Lse45.read_file_from_safe_dir(str(base), t)
        print(f"Request: {t} => {(content if content is not None else '(blocked or not found)')}")