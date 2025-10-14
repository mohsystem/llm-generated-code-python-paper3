
from typing import Optional


def largest_product(input_str: str, span: int) -> int:
    """\n    Computes the largest product among all possible series of a given span.\n    \n    Args:\n        input_str: A sequence of digits to analyze\n        span: The number of digits in each series\n        \n    Returns:\n        The largest product as an integer\n        \n    Raises:\n        ValueError: If inputs are invalid\n    """
    # Validate inputs
    if input_str is None:
        raise ValueError("Input cannot be None")
    if not isinstance(input_str, str):
        raise ValueError("Input must be a string")
    if not isinstance(span, int):
        raise ValueError("Span must be an integer")
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
    
    # Calculate product for each series
    for i in range(len(input_str) - span + 1):
        product = 1
        for j in range(i, i + span):
            digit = int(input_str[j])
            product *= digit
        max_product = max(max_product, product)
    
    return max_product


def main() -> None:
    """Test the largest_product function with various test cases."""
    test_cases = [
        ("63915", 3, 162),
        ("0123456789", 5, 15120),
        ("99999", 2, 81),
        ("12345", 1, 5),
        ("1", 1, 1)
    ]
    
    for i, (input_str, span, expected) in enumerate(test_cases, 1):
        try:
            result = largest_product(input_str, span)
            status = "PASS" if result == expected else "FAIL"
            print(f"Test {i}: {status} (Expected: {expected}, Got: {result})")
        except Exception as e:
            print(f"Test {i}: ERROR - {e}")


if __name__ == "__main__":
    main()
