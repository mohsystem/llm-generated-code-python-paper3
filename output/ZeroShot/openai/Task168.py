def tweakLetters(s, shifts):
    if s is None or shifts is None:
        raise ValueError("Inputs cannot be None.")
    if len(s) != len(shifts):
        raise ValueError("String length and shifts length must match.")
    res = []
    for ch, sh in zip(s, shifts):
        if 'a' <= ch <= 'z':
            adj = sh % 26
            res.append(chr((ord(ch) - ord('a') + adj) % 26 + ord('a')))
        else:
            res.append(ch)
    return ''.join(res)

if __name__ == "__main__":
    tests = [
        ("apple", [0, 1, -1, 0, -1]),  # aqold
        ("many", [0, 0, 0, -1]),       # manx
        ("rhino", [1, 1, 1, 1, 1]),    # sijop
        ("zzz", [1, 1, 1]),            # aaa
        ("abc", [27, -28, 52])         # bzc
    ]
    for s, arr in tests:
        try:
            print(tweakLetters(s, arr))
        except ValueError as e:
            print("Error:", e)