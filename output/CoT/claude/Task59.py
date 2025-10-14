
def accum(s):
    if not s:
        return ""
    
    result = []
    
    for i, c in enumerate(s):
        # Validate input - only letters allowed
        if not c.isalpha():
            continue
        
        # First character uppercase, rest lowercase repeated i times
        part = c.upper() + (c.lower() * i)
        result.append(part)
    
    return "-".join(result)


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", accum("abcd"))
    # Expected: A-Bb-Ccc-Dddd
    
    # Test case 2
    print("Test 2:", accum("RqaEzty"))
    # Expected: R-Qq-Aaa-Eeee-Zzzzz-Tttttt-Yyyyyyy
    
    # Test case 3
    print("Test 3:", accum("cwAt"))
    # Expected: C-Ww-Aaa-Tttt
    
    # Test case 4
    print("Test 4:", accum("ZpglnRxqenU"))
    # Expected: Z-Pp-Ggg-Llll-Nnnnn-Rrrrrr-Xxxxxxx-Qqqqqqqq-Eeeeeeeee-Nnnnnnnnnn-Uuuuuuuuuuuu
    
    # Test case 5
    print("Test 5:", accum("a"))
    # Expected: A
