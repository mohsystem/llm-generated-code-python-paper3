def largest_product(digits, span):
    """
    Computes the largest product of a series of adjacent digits of a specified span.
    
    Args:
        digits: The sequence of digits to analyze as a string.
        span: The number of digits in each series.
    
    Returns:
        The largest product found.
    
    Raises:
        ValueError: If the span is invalid or the input string contains non-digit characters.
    """
    if span < 0 or not digits.isdigit():
        raise ValueError("Invalid input: span must be non-negative and digits string must contain only digits.")
    if span > len(digits):
        raise ValueError("Invalid input: span cannot be greater than the length of the digits string.")

    if span == 0:
        return 1  # The product of an empty set is conventionally 1.

    max_product = 0
    for i in range(len(digits) - span + 1):
        series = digits[i:i + span]
        current_product = 1
        for digit in series:
            current_product *= int(digit)
        
        if current_product > max_product:
            max_product = current_product
            
    return max_product

if __name__ == "__main__":
    test_cases = [
        ("63915", 3),
        ("123456789", 4),
        ("1110987", 3),
        ("12345", 5),
        ("123", 4)
    ]

    for i, (digits, span) in enumerate(test_cases, 1):
        print(f"Test Case {i}: ('{digits}', {span})")
        try:
            result = largest_product(digits, span)
            print(f"Result: {result}")
        except ValueError as e:
            print(f"Result: {e}")
        print()