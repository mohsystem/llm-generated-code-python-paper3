from typing import Optional


def XO(s: Optional[str]) -> bool:
    if not isinstance(s, str):
        return False  # fail closed on invalid input
    x_count = 0
    o_count = 0
    for ch in s:
        if ch == 'x' or ch == 'X':
            x_count += 1
        elif ch == 'o' or ch == 'O':
            o_count += 1
    return x_count == o_count


if __name__ == "__main__":
    tests = ["ooxx", "xooxx", "ooxXm", "zpzpzpp", "zzoo"]
    expected = [True, False, True, True, False]
    for t, exp in zip(tests, expected):
        res = XO(t)
        print(f'XO("{t}") => {str(res).lower()} (expected {str(exp).lower()})')