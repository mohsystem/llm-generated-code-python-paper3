import math

def largest_product(input_str: str, span: int) -> int:
    """
    Computes the largest product of a series of adjacent digits.

    :param input_str: The sequence of digits as a string.
    :param span: The number of digits in each series.
    :return: The largest product found.
    :raises ValueError: if the input is invalid.
    """
    # 1. Input Validation
    if span < 0:
        raise ValueError("Span cannot be negative.")
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string.")
    if not input_str.isdigit() and input_str != "":
        raise ValueError("Input string must contain only digits.")
    if span > len(input_str):
        raise ValueError("Span cannot be greater than the input string length.")

    # 2. Edge Case
    if span == 0:
        return 1

    # 3. Calculation
    max_product = 0
    for i in range(len(input_str) - span + 1):
        series = input_str[i:i+span]
        
        # Convert character digits to integers and calculate product
        digits = [int(d) for d in series]
        current_product = math.prod(digits)
        
        if current_product > max_product:
            max_product = current_product
            
    return max_product

if __name__ == "__main__":
    # 5 Test Cases
    try:
        # Test Case 1: Example from prompt
        print(largest_product("63915", 3))

        # Test Case 2: A sequence containing zero
        print(largest_product("1234560789", 5))

        # Test Case 3: Span of 1
        print(largest_product("987654321", 1))

        # Test Case 4: Span equals the length of the input
        print(largest_product("12345", 5))

        # Test Case 5: Span of 0
        print(largest_product("111111", 0))
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")