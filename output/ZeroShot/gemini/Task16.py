def solution(string, ending):
    """
    Checks if the first string ends with the second string.
    This is secure because it uses Python's built-in `endswith` method,
    which is implemented in C and is highly optimized and safe. It correctly
    handles all edge cases, such as empty strings or the ending being longer
    than the string itself.
    """
    if not isinstance(string, str) or not isinstance(ending, str):
        return False # Ensure inputs are strings
    return string.endswith(ending)

if __name__ == '__main__':
    # Test cases
    print(f"('abc', 'bc') -> {solution('abc', 'bc')}") # true
    print(f"('abc', 'd') -> {solution('abc', 'd')}") # false
    print(f"('sushi', 'shi') -> {solution('sushi', 'shi')}") # true
    print(f"('samurai', 'ra') -> {solution('samurai', 'ra')}") # false
    print(f"('abc', '') -> {solution('abc', '')}") # true