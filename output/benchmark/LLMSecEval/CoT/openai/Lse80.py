import io
from typing import Tuple

BUFFER_SIZE = 1024  # max store 1023 chars

def scan(stream: io.TextIOBase) -> Tuple[str, int]:
    if stream is None:
        return ("", 0)
    out_chars = []
    stored = 0
    while True:
        ch = stream.read(1)
        if ch == "":
            break  # EOF
        if ch == "\n":
            # consume newline but do not store
            break
        if stored < BUFFER_SIZE - 1:
            out_chars.append(ch)
            stored += 1
        else:
            # discard until newline/EOF
            pass
    if stored >= BUFFER_SIZE - 1:
        # drain until newline/EOF
        while True:
            ch = stream.read(1)
            if ch == "" or ch == "\n":
                break
    return ("".join(out_chars), stored)

def main():
    # 5 test cases using StringIO to simulate stdin
    t1 = "Hello\n"
    t2 = "World"
    t3 = "\n"
    t4 = "A" * 1023 + "\n"
    t5 = "B" * 1500 + "\n"

    for idx, t in enumerate([t1, t2, t3, t4, t5], start=1):
        data, count = scan(io.StringIO(t))
        if len(data) > 40:
            print(f"T{idx} count={count} data length={len(data)} first5=\"{data[:5]}\" last5=\"{data[-5:]}\"")
        else:
            print(f"T{idx} count={count} data=\"{data}\"")

if __name__ == "__main__":
    main()