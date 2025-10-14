
def dig_pow(n, p):
    num_str = str(n)
    total = 0
    
    for i, digit in enumerate(num_str):
        total += int(digit) ** (p + i)
    
    if total % n == 0:
        return total // n
    return -1

if __name__ == "__main__":
    # Test case 1
    print(f"Test 1: n=89, p=1 -> {dig_pow(89, 1)}")  # Expected: 1
    
    # Test case 2
    print(f"Test 2: n=92, p=1 -> {dig_pow(92, 1)}")  # Expected: -1
    
    # Test case 3
    print(f"Test 3: n=695, p=2 -> {dig_pow(695, 2)}")  # Expected: 2
    
    # Test case 4
    print(f"Test 4: n=46288, p=3 -> {dig_pow(46288, 3)}")  # Expected: 51
    
    # Test case 5
    print(f"Test 5: n=114, p=3 -> {dig_pow(114, 3)}")  # Expected: 9
