# Chain-of-Through process embedded in comments for security and clarity.

from typing import List, Tuple
import tempfile
import os

MAX_RECORDS = 1_000_000

def read_and_sort_records(file_path: str) -> List[Tuple[str, str]]:
    """
    Read key=value lines from file, ignoring blank/comment/malformed lines,
    and return sorted list of (key, value) by key then value.
    """
    records: List[Tuple[str, str]] = []
    # Secure reading with UTF-8 and replacing invalid bytes
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            trimmed = line.strip()
            if not trimmed:
                continue
            if trimmed.startswith('#'):
                continue
            if '=' not in trimmed:
                continue
            key, value = trimmed.split('=', 1)
            key = key.strip()
            if not key:
                continue
            value = value.strip()
            records.append((key, value))
            if len(records) > MAX_RECORDS:
                raise IOError("Too many records; possible resource exhaustion.")
    records.sort(key=lambda kv: (kv[0], kv[1]))
    return records

def records_to_string(records: List[Tuple[str, str]]) -> str:
    return "[" + ", ".join(f"{k}={v}" for k, v in records) + "]"

def _write_temp(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="task94_", suffix=".txt")
    os.close(fd)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return path

def main():
    tests = [
        "b=2\na=1\nc=3\n",
        "  key2 =  z \n# comment\n\nkey1= a \n  # another comment\n",
        "k=2\nk=1\nk=3\n",
        "noequal\n=onlyvalue\nonlykey=\n mid = val = extra \n",
        "äpple=1\nbanana=2\nÁlpha=0\n",
    ]
    paths = []
    try:
        for t in tests:
            paths.append(_write_temp(t))
        for i, p in enumerate(paths, 1):
            out = read_and_sort_records(p)
            print(f"Test {i} result: {records_to_string(out)}")
    finally:
        for p in paths:
            try:
                os.remove(p)
            except Exception:
                pass

if __name__ == "__main__":
    main()