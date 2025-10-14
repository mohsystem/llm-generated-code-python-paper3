
def solution(str, ending):
    if str is None or ending is None:
        return False
    return str.endswith(ending)

# Test cases
if __name__ == "__main__":
    print(solution("abc", "bc"))      # True
    print(solution("abc", "d"))       # False
    print(solution("hello", "lo"))    # True
    print(solution("test", ""))       # True
    print(solution("", "test"))       # False
