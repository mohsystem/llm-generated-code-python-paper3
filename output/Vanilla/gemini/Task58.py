def XO(s):
    """
    Check to see if a string has the same amount of 'x's and 'o's.
    The method must return a boolean and be case-insensitive.
    The string can contain any char.
    """
    s_lower = s.lower()
    return s_lower.count('x') == s_lower.count('o')

if __name__ == '__main__':
    test_cases = ["ooxx", "xooxx", "ooxXm", "zpzpzpp", "zzoo"]
    for test in test_cases:
        result = XO(test)
        print(f'XO("{test}") => {result}')