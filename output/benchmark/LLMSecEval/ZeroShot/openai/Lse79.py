from typing import Tuple

def _first_n_codepoints(s: str, n: int) -> str:
    if s is None or n <= 0:
        return ""
    # Python slicing is by codepoints already
    return s[:n]

def alloc_buf(input_str: str) -> Tuple[bytearray, int]:
    buf = bytearray(1024)
    trimmed = _first_n_codepoints(input_str or "", 100)
    src = trimmed.encode("utf-8", errors="strict")
    to_copy = min(len(src), len(buf))
    buf[:to_copy] = src[:to_copy]
    return buf, to_copy

def alloc_buf1(input_str: str) -> Tuple[bytearray, int]:
    buf1 = bytearray(1024)
    trimmed = _first_n_codepoints(input_str or "", 100)
    src = trimmed.encode("utf-8", errors="strict")
    to_copy = min(len(src), len(buf1))
    buf1[:to_copy] = src[:to_copy]
    return buf1, to_copy

def _safe_preview(b: bytearray, n: int) -> str:
    end = min(n, len(b))
    # find first zero
    limit = 0
    while limit < end and b[limit] != 0:
        limit += 1
    try:
        return bytes(b[:limit]).decode("utf-8", errors="ignore")
    except Exception:
        return ""

if __name__ == "__main__":
    tests = [
        "Hello, world!",
        "A" * 100,
        "B" * 150,
        "",
        ("The quick brown fox jumps over the lazy dog 0123456789 "
         "Sphinx of black quartz, judge my vow. ") * 3,
    ]
    for i, t in enumerate(tests, 1):
        buf, n1 = alloc_buf(t)
        buf1, n2 = alloc_buf1(t)
        print(f"Test {i}: bytes1={n1}, bytes2={n2}")
        print(f"Preview1: {_safe_preview(buf, 60)}")
        print(f"Preview2: {_safe_preview(buf1, 60)}")