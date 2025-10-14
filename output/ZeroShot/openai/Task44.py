def process_input(s: str) -> str:
    if not isinstance(s, str):
        return "Invalid input"
    if len(s) > 256:
        return "Invalid input"
    for ch in s:
        if not _is_allowed(ch):
            return "Invalid input"
    out = []
    last_was_space = True  # trim leading and collapse
    for ch in s:
        if ch in (' ', '\t'):
            if not last_was_space:
                out.append(' ')
                last_was_space = True
        else:
            out.append(ch)
            last_was_space = False
    if out and out[-1] == ' ':
        out.pop()
    sanitized = ''.join(out)
    if not sanitized:
        return "Invalid input"
    digit_count = sum(1 for ch in sanitized if '0' <= ch <= '9')
    reversed_str = sanitized[::-1]
    return f"sanitized={sanitized}; length={len(sanitized)}; digits={digit_count}; reversed={reversed_str}"


def _is_allowed(c: str) -> bool:
    if len(c) != 1:
        return False
    o = ord(c)
    if 'a' <= c <= 'z':
        return True
    if 'A' <= c <= 'Z':
        return True
    if '0' <= c <= '9':
        return True
    if c in (' ', '\t', '_', '-', '.', ',', ':', '@'):
        return True
    return False


if __name__ == "__main__":
    tests = [
        "Hello World",
        "  Multiple    spaces   123  ",
        "Invalid!Chars#",
        "A_Very-Long.String,With:Allowed@Chars",
        ""
    ]
    for t in tests:
        print(f"Input: {t!r} -> {process_input(t)}")