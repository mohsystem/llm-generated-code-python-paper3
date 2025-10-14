from typing import List, Tuple

def solution(s: str, ending: str) -> bool:
    if not isinstance(s, str) or not isinstance(ending, str):
        return False  # Fail closed on invalid input
    return s.endswith(ending)

if __name__ == "__main__":
    tests: List[Tuple[str, str]] = [
        ("abc", "bc"),
        ("abc", "d"),
        ("", ""),
        ("hello", ""),
        ("你好世界", "世界"),
    ]
    for a, b in tests:
        print(f'solution("{a}", "{b}") = {solution(a, b)}')