def XO(s):
    """
    Checks if a string has the same amount of 'x's and 'o's, case-insensitively.
    
    :param s: The string to check. The string can contain any character.
    :return: True if the count of 'x's and 'o's is equal, False otherwise.
    """
    if s is None:
        return True # No 'x's or 'o's
        
    s_lower = s.lower()
    return s_lower.count('x') == s_lower.count('o')

if __name__ == "__main__":
    # Test cases
    print(f'XO("ooxx") => {XO("ooxx")}')          # Expected: true
    print(f'XO("xooxx") => {XO("xooxx")}')        # Expected: false
    print(f'XO("ooxXm") => {XO("ooxXm")}')        # Expected: true
    print(f'XO("zpzpzpp") => {XO("zpzpzpp")}')    # Expected: true
    print(f'XO("zzoo") => {XO("zzoo")}')          # Expected: false