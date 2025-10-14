from typing import List

def tweak_letters(s: str, shifts: List[int]) -> str:
    if not isinstance(s, str) or not isinstance(shifts, list):
        raise ValueError("Invalid input types.")
    if len(s) != len(shifts):
        raise ValueError("String length and shifts length must match.")
    out_chars: List[str] = []
    for i, ch in enumerate(s):
        if not ('a' <= ch <= 'z'):
            raise ValueError("Only lowercase a-z are supported.")
        delta = shifts[i] % 26
        pos = ord(ch) - ord('a')
        out_chars.append(chr(ord('a') + (pos + delta) % 26))
    return ''.join(out_chars)

def _run_test(input_s: str, shifts: List[int], expected: str) -> None:
    try:
        result = tweak_letters(input_s, shifts)
        print(f'tweak_letters("{input_s}", {shifts}) => "{result}"' + (f' | expected: "{expected}"' if expected is not None else ""))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    _run_test("apple", [0, 1, -1, 0, -1], "aqold")
    _run_test("many", [0, 0, 0, -1], "manx")
    _run_test("rhino", [1, 1, 1, 1, 1], "sijop")
    _run_test("zzz", [1, 1, 1], "aaa")
    _run_test("abc", [-1, 0, 1], "zbd")