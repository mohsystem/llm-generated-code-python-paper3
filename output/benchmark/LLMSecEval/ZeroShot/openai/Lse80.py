def scan(input_data: str, max_len: int = 1023):
    if not isinstance(input_data, str):
        return ("", 0)
    out_chars = []
    count = 0
    i = 0
    n = len(input_data)

    while i < n:
        ch = input_data[i]
        i += 1
        if ch == '\n':
            break
        if count < max_len:
            out_chars.append(ch)
            count += 1
        else:
            # discard until newline or end
            while i < n and input_data[i] != '\n':
                i += 1
            if i < n and input_data[i] == '\n':
                i += 1
            break
    return ("".join(out_chars), count)

if __name__ == "__main__":
    tests = [
        ("Test1", "Hello, World!\nTrailing"),
        ("Test2", ""),
        ("Test3", "NoNewline"),
        ("Test4", "A" * 1500 + "\nBBBB"),
        ("Test5", "Line1\nLine2\n"),
    ]
    for label, data in tests:
        out, count = scan(data)
        print(f"{label} -> count={count}, out=\"{out}\"")