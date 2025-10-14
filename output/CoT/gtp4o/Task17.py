# Chain-of-Through Secure Development Steps:
# 1) Problem understanding: Capitalize first character of each word; lower-case others. Return None for None or empty/whitespace-only input.
# 2) Security requirements: Handle None safely; preserve whitespace; avoid unsafe operations.
# 3) Secure coding generation: Iterate char-by-char; use str methods that are unicode-aware; no external input.
# 4) Code review: No mutation of input; safe handling for edge cases.
# 5) Secure code output: Tested with diverse cases.

def to_jaden_case(s):
    if s is None or s.strip() == "":
        return None
    result_chars = []
    start_of_word = True
    for ch in s:
        if ch.isspace():
            result_chars.append(ch)
            start_of_word = True
        else:
            if start_of_word:
                result_chars.append(ch.upper())
            else:
                result_chars.append(ch.lower())
            start_of_word = False
    return "".join(result_chars)

if __name__ == "__main__":
    tests = [
        "How can mirrors be real if our eyes aren't real",
        "most trees are blue",
        "",
        None,
        "a mixed-CASE input, with punctuation! and\ttabs"
    ]
    for t in tests:
        print(to_jaden_case(t))