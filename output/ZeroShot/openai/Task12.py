def highest_scoring_word(s: str) -> str:
    if s is None or len(s) == 0:
        return ""
    best_word = ""
    best_score = float("-inf")
    for w in s.split():
        score = sum((ord(ch) - 96) for ch in w if 'a' <= ch <= 'z')
        if score > best_score:
            best_score = score
            best_word = w
    return best_word


if __name__ == "__main__":
    tests = [
        "abad aa bb",
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
    ]
    for t in tests:
        print(highest_scoring_word(t))