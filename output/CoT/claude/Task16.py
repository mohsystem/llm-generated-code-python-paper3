
def solution(string, ending):
    # Input validation to prevent errors
    if string is None or ending is None:
        return False
    
    # Use built-in endswith method which is secure and efficient
    return string.endswith(ending)

# Test cases
if __name__ == "__main__":
    # Test case 1: Basic positive case
    print(solution("abc", "bc"))  # True
    
    # Test case 2: Basic negative case
    print(solution("abc", "d"))  # False
    
    # Test case 3: Empty ending (edge case)
    print(solution("abc", ""))  # True
    
    # Test case 4: Ending longer than string
    print(solution("ab", "abc"))  # False
    
    # Test case 5: Null safety test
    print(solution(None, "bc"))  # False
