from typing import List

def expanded_form(n: int) -> str:
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n <= 0:
        raise ValueError("Input must be a whole number greater than 0.")
    s = str(n)
    if len(s) > 20:
        raise ValueError("Input too large.")
    terms: List[str] = []
    length = len(s)
    for i, ch in enumerate(s):
        if ch != '0':
            zeros = length - 1 - i
            terms.append(ch + ('0' * zeros))
    return ' + '.join(terms)

if __name__ == "__main__":
    tests = [12, 42, 70304, 9000000, 105]
    for t in tests:
        try:
            print(f"{t} -> {expanded_form(t)}")
        except (TypeError, ValueError) as e:
            print(f"Error for input {t}: {e}")