
def find_nb(m):
    # Input validation
    if m <= 0:
        return -1
    
    n = 0
    total = 0
    
    # Iterate until sum equals or exceeds m
    while total < m:
        n += 1
        # Python handles large integers automatically
        total += n ** 3
    
    # Return n if exact match, otherwise -1
    return n if total == m else -1


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: {find_nb(1071225)} (Expected: 45)")
    print(f"Test 2: {find_nb(91716553919377)} (Expected: -1)")
    print(f"Test 3: {find_nb(4183059834009)} (Expected: 2022)")
    print(f"Test 4: {find_nb(24723578342962)} (Expected: -1)")
    print(f"Test 5: {find_nb(135)} (Expected: 5)")
