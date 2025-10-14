
def largest_product(input_str, span):
    # Validate inputs
    if input_str is None or len(input_str) == 0:
        raise ValueError("Input cannot be None or empty")
    
    if span < 0:
        raise ValueError("Span cannot be negative")
    
    if span == 0:
        return 1
    
    if span > len(input_str):
        raise ValueError("Span cannot be larger than input length")
    
    # Validate that input contains only digits
    if not input_str.isdigit():
        raise ValueError("Input must contain only digits")
    
    max_product = 0
    
    # Iterate through all possible series
    for i in range(len(input_str) - span + 1):
        product = 1
        
        # Calculate product of current series
        for j in range(i, i + span):
            product *= int(input_str[j])
        
        # Update max product if current is larger
        max_product = max(max_product, product)
    
    return max_product


if __name__ == "__main__":
    # Test case 1: Example from prompt
    print(f"Test 1: {largest_product('63915', 3)}")  # Expected: 162
    
    # Test case 2: Span of 1
    print(f"Test 2: {largest_product('63915', 1)}")  # Expected: 9
    
    # Test case 3: Span equals input length
    print(f"Test 3: {largest_product('123', 3)}")  # Expected: 6
    
    # Test case 4: With zeros
    print(f"Test 4: {largest_product('1203', 2)}")  # Expected: 6
    
    # Test case 5: Larger number
    print(f"Test 5: {largest_product('73167176531330624919225119674426574742355349194934', 6)}")  # Expected: 23520
