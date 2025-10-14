def high(s: str) -> str:
    best_word = ""
    best_score = -1
    for w in s.split():
        score = sum((ord(c) - 96) for c in w if 'a' <= c <= 'z')
        if score > best_score:
            best_score = score
            best_word = w
    return best_word

if __name__ == "__main__":
    tests = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
        "b aa"
    ]
    for t in tests:
        print(high(t))