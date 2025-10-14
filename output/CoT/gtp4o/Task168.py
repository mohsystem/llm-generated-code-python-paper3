# Task168 - Python implementation
# Chain-of-Through process in code generation:
# 1) Problem understanding: Shift lowercase letters by offsets with wrap-around.
# 2) Security requirements: Prevent index errors, handle None inputs.
# 3) Secure coding generation: Use safe modulo for negatives; process only lowercase.
# 4) Code review: Checked bounds and conversions.
# 5) Secure code output: Provide final function and tests.

def tweakLetters(s, arr):
    if s is None:
        return ""
    if arr is None:
        arr = []
    n = len(s)
    m = len(arr)
    out = []
    for i, ch in enumerate(s):
        if 'a' <= ch <= 'z' and i < m:
            base = ord(ch) - ord('a')
            shift = arr[i] % 26
            ni = (base + shift) % 26
            out.append(chr(ord('a') + ni))
        elif 'a' <= ch <= 'z':
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)

if __name__ == "__main__":
    print(tweakLetters("apple", [0, 1, -1, 0, -1]))  # aqold
    print(tweakLetters("many", [0, 0, 0, -1]))       # manx
    print(tweakLetters("rhino", [1, 1, 1, 1, 1]))    # sijop
    print(tweakLetters("zzz", [1, 1, 1]))            # aaa
    print(tweakLetters("abc", [-1, -1, -1]))         # zab