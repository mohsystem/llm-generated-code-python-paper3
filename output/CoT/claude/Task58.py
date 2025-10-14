
def XO(s):
    if s is None:
        return True
    
    lower_str = s.lower()
    count_x = 0
    count_o = 0
    
    for c in lower_str:
        if c == 'x':
            count_x += 1
        elif c == 'o':
            count_o += 1
    
    return count_x == count_o

if __name__ == "__main__":
    print("Test 1: XO('ooxx') =", XO("ooxx"))
    print("Test 2: XO('xooxx') =", XO("xooxx"))
    print("Test 3: XO('ooxXm') =", XO("ooxXm"))
    print("Test 4: XO('zpzpzpp') =", XO("zpzpzpp"))
    print("Test 5: XO('zzoo') =", XO("zzoo"))
