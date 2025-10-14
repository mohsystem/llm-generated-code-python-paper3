import os
import shutil
from pathlib import Path

def upload_file(source_path: str, dest_dir: str, new_name: str | None = None) -> str:
    src = Path(source_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Source file does not exist: {src}")
    dest_dir_path = Path(dest_dir)
    dest_dir_path.mkdir(parents=True, exist_ok=True)
    final_name = new_name if new_name and new_name.strip() else src.name
    dest = dest_dir_path / final_name
    shutil.copy2(src, dest)
    return str(dest.resolve())

if __name__ == "__main__":
    fixtures = Path("fixtures_py")
    uploads = Path("uploads_py")
    fixtures.mkdir(parents=True, exist_ok=True)
    uploads.mkdir(parents=True, exist_ok=True)

    f1 = fixtures / "pfile1.txt"
    f2 = fixtures / "pfile2.txt"
    f3 = fixtures / "pfile3.log"
    f4 = fixtures / "image.dat"
    f5 = fixtures / "notes.md"

    f1.write_text("Hello from Python file1", encoding="utf-8")
    f2.write_text("Hello from Python file2", encoding="utf-8")
    f3.write_text("Log content", encoding="utf-8")
    f4.write_bytes(b"\x00\x01\x02binary content")
    f5.write_text("# Python Notes\nEntry", encoding="utf-8")

    print(upload_file(str(f1), str(uploads), None))
    print(upload_file(str(f2), str(uploads), "renamed_pfile2.txt"))
    print(upload_file(str(f3), str(uploads / "nestedA" / "nestedB"), None))
    print(upload_file(str(f4), str(uploads), "image_copy.dat"))
    print(upload_file(str(f5), str(uploads / "docs"), "notes_copy.md"))