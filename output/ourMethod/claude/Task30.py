
def longest(s1: str, s2: str) -> str:
    if s1 is None or s2 is None:
        raise ValueError("Input strings must not be None")
    
    if not isinstance(s1, str) or not isinstance(s2, str):
        raise TypeError("Inputs must be strings")
    
    if len(s1) > 10000 or len(s2) > 10000:
        raise ValueError("Input strings exceed maximum length")
    
    for c in s1:
        if c < 'a' or c > 'z':
            raise ValueError("Input must contain only lowercase letters a-z")
    
    for c in s2:
        if c < 'a' or c > 'z':
            raise ValueError("Input must contain only lowercase letters a-z")
    
    distinct_chars = set(s1) | set(s2)
    return ''.join(sorted(distinct_chars))


if __name__ == "__main__":
    print(longest("xyaabbbccccdefww", "xxxxyyyyabklmopq"))
    print(longest("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"))
    print(longest("abc", "xyz"))
    print(longest("aaa", "bbb"))
    print(longest("", "abc"))
