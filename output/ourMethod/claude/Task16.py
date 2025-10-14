
def solution(str_val: str, ending: str) -> bool:
    """\n    Check if str_val ends with ending.\n    \n    Args:\n        str_val: The string to check\n        ending: The suffix to look for\n        \n    Returns:\n        True if str_val ends with ending, False otherwise\n    """
    # Validate inputs
    if str_val is None or ending is None:
        return False
    
    if not isinstance(str_val, str) or not isinstance(ending, str):
        return False
    
    # Empty ending always matches
    if len(ending) == 0:
        return True
    
    # Check if ending is longer than string
    if len(ending) > len(str_val):
        return False
    
    # Check if str_val ends with ending
    return str_val.endswith(ending)


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
    print(solution("", "test"))  # False
