from typing import List, Sequence

MAX_LEN = 1 << 20  # 1 MiB max input length

def process_args(args: Sequence[object]) -> str:
    # First if: exactly one argument
    if args is None or len(args) != 1:
        raise ValueError("invalid args")
    s = args[0]
    # Check that the argument is a string
    if not isinstance(s, str):
        raise ValueError("invalid arg")
    if len(s) > MAX_LEN:
        raise ValueError("too long")

    buf = list(s)

    # For loop 1: trim trailing whitespace excluding CR/LF (space, tab, vertical tab, form feed)
    i = len(buf) - 1
    while i >= 0 and buf[i] in (' ', '\t', '\v', '\f'):
        i -= 1
    end1 = i + 1

    # For loop 2: trim trailing newlines (LF, CR)
    j = end1 - 1
    while j >= 0 and buf[j] in ('\n', '\r'):
        j -= 1
    end2 = j + 1

    result = ''.join(buf[:end2])
    # Last line: "null terminate" (conceptual in Python)
    _null_terminated = result + '\0'
    return result


def _run_tests() -> None:
    tests: List[Sequence[object]] = [
        ["hello   "],              # trailing spaces
        ["world\t\t\n"],           # tabs then newline
        ["line with spaces \r\n\n"],  # spaces then CRLF+LF
        ["no-trim"],               # no trailing whitespace/newlines
        ["invalid", "extra"]       # invalid: more than one argument
    ]
    for idx, t in enumerate(tests, 1):
        try:
            out = process_args(t)
            print(f"Test {idx} -> [{out}] len={len(out)}")
        except Exception:
            print(f"Test {idx} -> error")


if __name__ == "__main__":
    _run_tests()