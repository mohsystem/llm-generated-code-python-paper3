import math

def largest_product(input_str: str, span: int) -> int:
    """
    Computes the largest product of a series of adjacent digits of a specified span.

    Args:
        input_str: The sequence of digits to analyze.
        span: The number of digits in each series.

    Returns:
        The largest product.

    Raises:
        ValueError: if the input is invalid.
    """
    # 1. Input Validation
    if span < 0:
        raise ValueError("Span must not be negative.")
    if span > len(input_str):
        raise ValueError("Span must be smaller than or equal to the length of the input string.")
    if not input_str.isdigit() and input_str:
        raise ValueError("Input string must only contain digits.")

    # 2. Handle edge case: span is 0, the product of an empty set is 1.
    if span == 0:
        return 1

    # 3. Main Algorithm
    digits = [int(d) for d in input_str]
    max_prod = 0
    
    for i in range(len(digits) - span + 1):
        series = digits[i : i + span]
        current_prod = math.prod(series)
        if current_prod > max_prod:
            max_prod = current_prod
            
    return max_prod

def main():
    """Main function with test cases."""
    test_cases = [
        {"input": "63915", "span": 3, "expected": 162},
        {"input": "1027839564", "span": 4, "expected": 5832},
        {"input": "12345", "span": 5, "expected": 120},
        {"input": "12345", "span": 0, "expected": 1},
        {"input": "73167176531330624919225119674426574742355349194934", "span": 6, "expected": 23520},
    ]

    for i, tc in enumerate(test_cases):
        try:
            result = largest_product(tc["input"], tc["span"])
            print(f"Test Case {i + 1}:")
            print(f"Input: \"{tc['input']}\", Span: {tc['span']}")
            print(f"Result: {result}")
            print(f"Expected: {tc['expected']}")
            print(f"Status: {'Passed' if result == tc['expected'] else 'Failed'}")
        except ValueError as e:
            print(f"Test Case {i + 1} threw an exception: {e}")
        print("--------------------")

    # Test invalid cases
    try:
        largest_product("123", 4)
    except ValueError as e:
        print(f"Test Case 6 (Invalid Span): Passed - {e}")
    try:
        largest_product("1a2", 2)
    except ValueError as e:
        print(f"Test Case 7 (Invalid Chars): Passed - {e}")

if __name__ == "__main__":
    main()