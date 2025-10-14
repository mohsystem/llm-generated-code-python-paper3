
def dig_pow(n, p):
    # Input validation to prevent security issues
    if n <= 0 or p <= 0:
        return -1
    
    # Convert n to string to extract digits safely
    n_str = str(n)
    total_sum = 0
    
    # Calculate sum of digits raised to consecutive powers
    for i, digit_char in enumerate(n_str):
        # Validate character is a digit
        if not digit_char.isdigit():
            return -1
        
        digit = int(digit_char)
        power = p + i
        
        try:
            # Calculate power and add to sum
            pow_result = digit ** power
            total_sum += pow_result
        except (OverflowError, ValueError):
            return -1
    
    # Check if sum is divisible by n
    if total_sum % n == 0:
        return total_sum // n
    
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
    print(f"Test 5: n=1, p=1 -> {dig_pow(1, 1)}")  # Expected: 1
