
def largest_product(input_str, span):
    # Handle edge cases
    if input_str is None or span < 0:
        raise ValueError("Invalid input or span")
    
    # Remove non-digit characters
    digits = ''.join(filter(str.isdigit, input_str))
    
    if span > len(digits):
        raise ValueError("Span is larger than input length")
    
    if span == 0:
        return 1
    
    max_product = 0
    
    # Iterate through all possible series
    for i in range(len(digits) - span + 1):
        product = 1
        for j in range(i, i + span):
            product *= int(digits[j])
        max_product = max(max_product, product)
    
    return max_product


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", largest_product("63915", 3))  # Expected: 162
    
    # Test case 2
    print("Test 2:", largest_product("123456789", 4))  # Expected: 3024
    
    # Test case 3
    print("Test 3:", largest_product("0123456789", 3))  # Expected: 504
    
    # Test case 4
    print("Test 4:", largest_product("99999", 2))  # Expected: 81
    
    # Test case 5
    print("Test 5:", largest_product("1234", 1))  # Expected: 4
