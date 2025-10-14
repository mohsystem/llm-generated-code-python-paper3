from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class BufferResult:
    success: bool
    content: str
    truncated: bool
    message: str


def _sanitize(s: str) -> str:
    if s is None:
        return ""
    # Allow printable ASCII (32-126), tab, and newline
    allowed: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch == "\n" or ch == "\t" or (32 <= o <= 126):
            allowed.append(ch)
    return "".join(allowed)


def handle_input_to_fixed_buffer(input_str: str, buffer_size: int) -> BufferResult:
    if buffer_size < 1 or buffer_size > 4096:
        return BufferResult(False, "", False, "Invalid buffer size")
    sanitized = _sanitize(input_str)
    copy_len = min(len(sanitized), buffer_size)
    # Simulate fixed-size buffer via slicing up to capacity
    content = sanitized[:copy_len]
    truncated = len(sanitized) > copy_len
    return BufferResult(True, content, truncated, "OK")


def main() -> None:
    buf_size = 16
    tests = [
        "Hello World",                      # fits
        "",                                 # empty
        "This is a very long input string!!!",  # long
        "Hi\u0001\u0002 there",             # control chars
        "1234567890ABCDEF",                 # boundary
    ]
    for i, t in enumerate(tests, 1):
        res = handle_input_to_fixed_buffer(t, buf_size)
        print(f"Test {i}: {res}")


if __name__ == "__main__":
    main()