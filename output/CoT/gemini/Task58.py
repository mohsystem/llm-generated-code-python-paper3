def XO(s):
    """
    Check to see if a string has the same amount of 'x's and 'o's.
    The method must return a boolean and be case insensitive.
    The string can contain any char.
    """
    if s is None:
        return True
    
    # Convert string to lowercase and count occurrences of 'x' and 'o'
    s_lower = s.lower()
    return s_lower.count('x') == s_lower.count('o')

# main method with 5 test cases
if __name__ == '__main__':
    print(f"ooxx -> {XO('ooxx')}")          # Expected: true
    print(f"xooxx -> {XO('xooxx')}")        # Expected: false
    print(f"ooxXm -> {XO('ooxXm')}")        # Expected: true
    print(f"zpzpzpp -> {XO('zpzpzpp')}")    # Expected: true
    print(f"zzoo -> {XO('zzoo')}")          # Expected: false