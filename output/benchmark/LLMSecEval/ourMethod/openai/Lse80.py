import io
from typing import Tuple

MAX_BUFFER_SIZE = 1024  # bytes; will store at most 1023 characters

def scan(stream: io.BufferedReader, max_size: int = MAX_BUFFER_SIZE) -> Tuple[str, int]:
    """
    Reads from the provided binary stream up to max_size-1 bytes or until a newline is encountered.
    The newline (if encountered during reading) is consumed but not stored.
    Returns a tuple (text, count) where count is the number of bytes stored.
    """
    if max_size <= 0:
        return ("", 0)

    limit = max(0, max_size - 1)
    buf = bytearray()
    while len(buf) < limit:
        b = stream.read(1)
        if not b:
            break  # EOF
        if b == b'\n':
            break  # consume newline; do not store
        buf += b

    # Do not attempt to read further if limit reached; leave any newline for the next consumer
    s = buf.decode('utf-8', errors='strict')
    return (s, len(buf))

def _visible(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if ch == '\n':
            out.append("\\n")
        elif ch == '\r':
            out.append("\\r")
        elif ch == '\t':
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append("\\x%02X" % code)
        else:
            out.append(ch)
    return "".join(out)

if __name__ == "__main__":
    # Test case 1: Simple line with newline
    t1 = b"Hello\nWorld"
    r1 = scan(io.BufferedReader(io.BytesIO(t1)))
    print(f"T1 count={r1[1]} text=\"{_visible(r1[0])}\"")

    # Test case 2: Empty line (just newline)
    t2 = b"\n"
    r2 = scan(io.BufferedReader(io.BytesIO(t2)))
    print(f"T2 count={r2[1]} text=\"{_visible(r2[0])}\"")

    # Test case 3: Longer than buffer (1200 'A's and newline)
    t3 = b"A" * 1200 + b"\n"
    r3 = scan(io.BufferedReader(io.BytesIO(t3)))
    print(f"T3 count={r3[1]} (expected 1023) text_len={len(r3[0])}")

    # Test case 4: No newline before EOF
    t4 = b"NoNewlineEOF"
    r4 = scan(io.BufferedReader(io.BytesIO(t4)))
    print(f"T4 count={r4[1]} text=\"{_visible(r4[0])}\"")

    # Test case 5: CRLF before next data
    t5 = b"CR\rLF\r\nNext"
    r5 = scan(io.BufferedReader(io.BytesIO(t5)))
    print(f"T5 count={r5[1]} text=\"{_visible(r5[0])}\"")