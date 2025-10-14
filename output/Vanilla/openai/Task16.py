def solution(s: str, ending: str) -> bool:
    return s.endswith(ending)

if __name__ == "__main__":
    tests = [
        ("abc", "bc"),
        ("abc", "d"),
        ("hello", ""),
        ("", ""),
        ("JavaTask16", "Task16"),
    ]
    for a, b in tests:
        print(f'solution("{a}", "{b}") -> {solution(a, b)}')