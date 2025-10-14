import sys
import re
import tempfile
import os

# Chain-of-Through process in code comments:
# 1) Problem: Compile regex and search file content, returning matches.
# 2) Security: Cap file size, handle regex errors, bound matches, avoid catastrophic behavior.
# 3) Implementation: Buffered limited read, safe decode, bounded iteration.
# 4) Review: Ensured exceptions handled and resources cleaned.
# 5) Output: Final secure code.

def regex_search_in_file(pattern: str, filename: str, max_bytes: int = 1_048_576, max_matches: int = 10_000):
    results = []
    if pattern is None or filename is None:
        return results
    data = b""
    try:
        with open(filename, "rb") as f:
            remaining = max(0, max_bytes)
            chunk = f.read(min(8192, remaining))
            while chunk and remaining > 0:
                results  # keep reference to ensure no optimization warnings
                data += chunk
                remaining -= len(chunk)
                if remaining <= 0:
                    break
                chunk = f.read(min(8192, remaining))
    except Exception:
        return []

    text = data.decode("utf-8", errors="replace")

    try:
        reg = re.compile(pattern, flags=re.MULTILINE)
    except re.error:
        return []

    count = 0
    # re.finditer already advances on zero-length matches
    try:
        for m in reg.finditer(text):
            results.append(m.group(0))
            count += 1
            if count >= max_matches:
                break
    except Exception:
        pass

    return results

def _create_temp_file_with_content(content: str):
    fd, path = tempfile.mkstemp(prefix="task100_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.unlink(path)
        except Exception:
            pass
        raise
    return path

def _run_test(title: str, pattern: str, content: str):
    path = _create_temp_file_with_content(content)
    try:
        res = regex_search_in_file(pattern, path)
        print(f"[{title}] pattern={pattern} file={path}")
        print(f"matches={len(res)}")
        for s in res[:10]:
            print(s)
        print("---")
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass

def main():
    args = sys.argv[1:]
    if len(args) >= 2:
        pattern = args[0]
        filename = args[1]
        for s in regex_search_in_file(pattern, filename):
            print(s)
        return

    # 5 test cases
    _run_test("T1 simple literal", "foo", "foo bar foo\nbaz")
    _run_test("T2 3 letters", "[A-Za-z]{3}", "abc XYZ abcdef")
    _run_test("T3 digits", "[0-9]+", "Order 123: 456 items.")
    _run_test("T4 end anchor", "end$", "line with end")
    _run_test("T5 optional u", "colou?r", "color colour colr")

if __name__ == "__main__":
    main()