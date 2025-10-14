import sys
import unicodedata

def process_input(s: str) -> str:
    if s is None:
        return ""
    out = []
    in_space = False

    for ch in s:
        cat = unicodedata.category(ch)
        is_whitespace = ch.isspace()
        is_control = (cat in ('Cc', 'Cf')) and not is_whitespace  # drop control but preserve whitespace

        if is_control:
            continue

        if is_whitespace:
            if out and not in_space:
                out.append(' ')
                in_space = True
        else:
            out.append(ch)
            in_space = False

    # Trim trailing space if any
    if out and out[-1] == ' ':
        out.pop()

    return ''.join(out)

if __name__ == "__main__":
    # Five test cases
    tests = [
        "Hello,  World!",                       # double spaces
        "   Leading and trailing   ",           # trim and collapse spaces
        "Line1\t\tLine2",                       # tabs collapsed to single space
        "Control\u0007Char and \u0009 tabs",    # remove bell, keep whitespace collapsed
        "aaaaa     bbbbb     ccccc    "         # collapse spaces and trim
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: [{process_input(t)}]")

    # If user provides arguments, treat them as user input
    if len(sys.argv) > 1:
        user_input = " ".join(sys.argv[1:])
        print(f"User Input: [{process_input(user_input)}]")