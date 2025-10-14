import os
import tempfile
from typing import List, Tuple

MAX_LINE_LEN = 1_048_576

def _is_comment_or_empty(s: str) -> bool:
    t = s.strip()
    return not t or t.startswith("#") or t.startswith(";")

def read_and_sort_key_value_file(file_path: str) -> List[str]:
    if not file_path:
        raise ValueError("file_path must not be empty")
    pairs: List[Tuple[str, str]] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if len(line) > MAX_LINE_LEN:
                # Skip overly long lines
                continue
            t = line.strip()
            if _is_comment_or_empty(t):
                continue
            idx = t.find("=")
            if idx <= 0:
                continue
            key = t[:idx].strip()
            value = t[idx+1:].strip()
            if not key:
                continue
            pairs.append((key, value))
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return [f"{k}={v}" for k, v in pairs]

def _create_temp_file_with_content(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="task94_test_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="strict") as f:
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

def _print_result(title: str, result: List[str]) -> None:
    print(title)
    for s in result:
        print(s)
    print("----")

if __name__ == "__main__":
    c1 = (
        "# Comment line\n"
        "a=1\n"
        "b= 2\n"
        " c =3 \n"
        "d=4\n"
        "invalidline\n"
        "=novalue\n"
        "e=\n"
        ";comment\n"
        "f = value with spaces  \n"
    )
    c2 = (
        "z = last\n"
        "a = first\n"
        "m = middle\n"
        "a = duplicate\n"
        "x=42\n"
        "y=100\n"
    )
    c3 = (
        " key = value=with=equals\n"
        " spaced key = spaced value \n"
        "# comment\n"
        "emptykey= \n"
        " = bad\n"
        "onlykey=\n"
    )
    c4 = (
        "café=au lait\n"
        "naïve=façade\n"
        "日本=語\n"
        "ключ=значение\n"
    )
    c5 = (
        "delta=4\r\n"
        "alpha=1\r\n"
        "charlie=3\r\n"
        "bravo=2\r\n"
        "alpha=0\r\n"
    )

    p1 = _create_temp_file_with_content(c1)
    p2 = _create_temp_file_with_content(c2)
    p3 = _create_temp_file_with_content(c3)
    p4 = _create_temp_file_with_content(c4)
    p5 = _create_temp_file_with_content(c5)

    try:
        _print_result("Test 1", read_and_sort_key_value_file(p1))
        _print_result("Test 2", read_and_sort_key_value_file(p2))
        _print_result("Test 3", read_and_sort_key_value_file(p3))
        _print_result("Test 4", read_and_sort_key_value_file(p4))
        _print_result("Test 5", read_and_sort_key_value_file(p5))
    finally:
        for p in (p1, p2, p3, p4, p5):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass