
def XO(s):
    if s is None:
        return True
    
    s_lower = s.lower()
    count_x = 0
    count_o = 0
    
    for ch in s_lower:
        if ch == 'x':
            count_x += 1
        elif ch == 'o':
            count_o += 1
    
    return count_x == count_o


if __name__ == "__main__":
    print(f"Test 1: XO('ooxx') = {XO('ooxx')} (expected: True)")
    print(f"Test 2: XO('xooxx') = {XO('xooxx')} (expected: False)")
    print(f"Test 3: XO('ooxXm') = {XO('ooxXm')} (expected: True)")
    print(f"Test 4: XO('zpzpzpp') = {XO('zpzpzpp')} (expected: True)")
    print(f"Test 5: XO('zzoo') = {XO('zzoo')} (expected: False)")
