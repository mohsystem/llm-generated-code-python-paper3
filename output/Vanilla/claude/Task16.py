
def solution(string, ending):
    return string.endswith(ending)

if __name__ == "__main__":
    # Test case 1
    print(solution("abc", "bc"))  # True
    
    # Test case 2
    print(solution("abc", "d"))  # False
    
    # Test case 3
    print(solution("hello world", "world"))  # True
    
    # Test case 4
    print(solution("test", ""))  # True
    
    # Test case 5
    print(solution("programming", "ing"))  # True
