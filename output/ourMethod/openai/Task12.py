from typing import Optional

MAX_LEN = 1_000_000

def highest_scoring_word(s: str) -> str:
    if not isinstance(s, str):
        raise ValueError("Input must be a string")
    if len(s) > MAX_LEN:
        raise ValueError("Input too long")

    best_start = -1
    best_len = 0
    best_score = -1

    cur_start = -1
    cur_len = 0
    cur_score = 0

    for i, ch in enumerate(s):
        if not ch.isspace():
            if cur_len == 0:
                cur_start = i
            sc = (ord('a') <= ord(ch) <= ord('z')) and (ord(ch) - ord('a') + 1) or 0
            cur_score += sc
            cur_len += 1
        else:
            if cur_len > 0:
                if cur_score > best_score:
                    best_score = cur_score
                    best_start = cur_start
                    best_len = cur_len
                cur_len = 0
                cur_score = 0

    if cur_len > 0:
        if cur_score > best_score:
            best_score = cur_score
            best_start = cur_start
            best_len = cur_len

    if best_start == -1:
        return ""
    return s[best_start:best_start + best_len]


if __name__ == "__main__":
    tests = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
        "abad zzz a b c",
    ]
    for t in tests:
        res = highest_scoring_word(t)
        print(f'Input: "{t}" -> Highest: "{res}"')