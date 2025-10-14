
def find_nb(m):
    n = 0
    sum_cubes = 0
    
    while sum_cubes < m:
        n += 1
        sum_cubes += n ** 3
    
    return n if sum_cubes == m else -1

# Test cases
if __name__ == "__main__":
    print("Test 1: find_nb(1071225) =", find_nb(1071225))  # Expected: 45
    print("Test 2: find_nb(91716553919377) =", find_nb(91716553919377))  # Expected: -1
    print("Test 3: find_nb(4183059834009) =", find_nb(4183059834009))  # Expected: 2022
    print("Test 4: find_nb(24723578342962) =", find_nb(24723578342962))  # Expected: -1
    print("Test 5: find_nb(135) =", find_nb(135))  # Expected: 5
