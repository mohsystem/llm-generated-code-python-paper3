def solution(s, ending):
    if not isinstance(s, str) or not isinstance(ending, str):
        return False
    if len(ending) > len(s):
        return False
    return s.endswith(ending)

if __name__ == "__main__":
    tests = [
        ("abc", "bc"),
        ("abc", "d"),
        ("", ""),
        ("abc", ""),
        ("a", "ab"),
    ]
    for t in tests:
        print("true" if solution(t[0], t[1]) else "false")