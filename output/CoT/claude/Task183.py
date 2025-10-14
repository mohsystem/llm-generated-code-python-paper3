
def largest_product(input_str, span):
    # Input validation
    if input_str is None or len(input_str) == 0:
        raise ValueError("Input cannot be None or empty")
    
    if span < 0:
        raise ValueError("Span cannot be negative")
    
    if span == 0:
        return 1
    
    if span > len(input_str):
        raise ValueError("Span cannot be greater than input length")
    
    # Validate that input contains only digits
    if not input_str.isdigit():
        raise ValueError("Input must contain only digits")
    
    max_product = 0
    
    # Iterate through all possible series
    for i in range(len(input_str) - span + 1):
        product = 1
        
        # Calculate product for current series
        for j in range(i, i + span):
            digit = int(input_str[j])
            product *= digit
        
        # Update maximum product
        if product > max_product:
            max_product = product
    
    return max_product


if __name__ == "__main__":
    # Test case 1: Example from problem
    print("Test 1:", largest_product("63915", 3))  # Expected: 162
    
    # Test case 2: Single digit span
    print("Test 2:", largest_product("987654321", 1))  # Expected: 9
    
    # Test case 3: Full length span
    print("Test 3:", largest_product("123", 3))  # Expected: 6
    
    # Test case 4: Contains zeros
    print("Test 4:", largest_product("1020304", 3))  # Expected: 24
    
    # Test case 5: Larger span
    print("Test 5:", largest_product("73167176531330624919225119674426574742355349194934", 6))  # Expected: 23520
