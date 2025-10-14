
def findNb(m):
    n = 0
    sum_cubes = 0
    
    while sum_cubes < m:
        n += 1
        sum_cubes += n ** 3
    
    return n if sum_cubes == m else -1

# Test cases
if __name__ == "__main__":
    print("Test 1:", findNb(1071225), "(Expected: 45)")
    print("Test 2:", findNb(91716553919377), "(Expected: -1)")
    print("Test 3:", findNb(4183059834009), "(Expected: 2022)")
    print("Test 4:", findNb(24723578342962), "(Expected: -1)")
    print("Test 5:", findNb(135), "(Expected: 5)")
