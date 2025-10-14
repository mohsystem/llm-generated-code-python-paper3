
def XO(s):
    if s is None:
        return True
    
    lower_str = s.lower()
    x_count = lower_str.count('x')
    o_count = lower_str.count('o')
    
    return x_count == o_count


if __name__ == "__main__":
    # Test case 1
    print(f"XO('ooxx') = {XO('ooxx')}")  # Expected: True
    
    # Test case 2
    print(f"XO('xooxx') = {XO('xooxx')}")  # Expected: False
    
    # Test case 3
    print(f"XO('ooxXm') = {XO('ooxXm')}")  # Expected: True
    
    # Test case 4
    print(f"XO('zpzpzpp') = {XO('zpzpzpp')}")  # Expected: True
    
    # Test case 5
    print(f"XO('zzoo') = {XO('zzoo')}")  # Expected: False
