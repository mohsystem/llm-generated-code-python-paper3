from typing import List

MAX_LEN = 100_000

def spin_words(s: str) -> str:
    if not isinstance(s, str):
        raise ValueError("Input must be a string")
    n = len(s)
    if n < 1 or n > MAX_LEN:
        raise ValueError("Input length out of allowed range")

    # Validate: only letters and spaces
    for ch in s:
        if ch != ' ' and not ch.isalpha():
            raise ValueError("Input contains invalid characters")

    result_chars: List[str] = []
    word_chars: List[str] = []

    for ch in s:
        if ch == ' ':
            if len(word_chars) >= 5:
                result_chars.extend(reversed(word_chars))
            else:
                result_chars.extend(word_chars)
            word_chars.clear()
            result_chars.append(' ')
        else:
            word_chars.append(ch)

    if len(word_chars) >= 5:
        result_chars.extend(reversed(word_chars))
    else:
        result_chars.extend(word_chars)

    return ''.join(result_chars)

if __name__ == "__main__":
    tests = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "spin",
        "Spinning works right now"
    ]
    for t in tests:
        try:
            print(spin_words(t))
        except ValueError:
            print("ERROR")