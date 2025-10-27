from typing import Tuple

# Reads up to 1023 characters from input until a newline or end-of-input.
# The newline (if present) is consumed but not stored.
# Returns a tuple: (stored_text, count_of_stored_chars, total_consumed_chars)
def scan(input_str: str) -> Tuple[str, int, int]:
    if input_str is None:
        input_str = ""
    out_chars = []
    count = 0
    consumed = 0
    for ch in input_str:
        if ch == '\n':
            consumed += 1
            break
        if count < 1023:
            out_chars.append(ch)
            count += 1
        consumed += 1
    return ("".join(out_chars), count, consumed)

if __name__ == "__main__":
    tests = [
        "hello\nworld",             # normal line with newline
        "\nstart",                  # newline first
        "a"*1100 + "\nNEXT",        # longer than 1023, then newline
        "no newline here",          # no newline
        ""                          # empty input
    ]
    for i, t in enumerate(tests, 1):
        text, count, consumed = scan(t)
        print(f"Test {i}: text=\"{text}\", count={count}, consumed={consumed}")