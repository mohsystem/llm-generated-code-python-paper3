
def XO(input_str: str) -> bool:
    """\n    Check if a string has the same amount of 'x's and 'o's (case insensitive).\n    \n    Args:\n        input_str: The string to check\n        \n    Returns:\n        bool: True if counts are equal, False otherwise\n        \n    Raises:\n        TypeError: If input is not a string\n        ValueError: If input length exceeds maximum allowed\n    """
    # Validate input type
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    # Validate input length to prevent excessive processing
    if len(input_str) > 100000:
        raise ValueError("Input length exceeds maximum allowed")
    
    x_count = 0
    o_count = 0
    
    # Convert to lowercase for case-insensitive comparison
    lower_str = input_str.lower()
    
    for char in lower_str:
        if char == 'x':
            x_count += 1
        elif char == 'o':
            o_count += 1
    
    return x_count == o_count


if __name__ == "__main__":
    # Test case 1
    print(f"Test 1 - XO('ooxx'): {XO('ooxx')} (expected: True)")
    
    # Test case 2
    print(f"Test 2 - XO('xooxx'): {XO('xooxx')} (expected: False)")
    
    # Test case 3
    print(f"Test 3 - XO('ooxXm'): {XO('ooxXm')} (expected: True)")
    
    # Test case 4
    print(f"Test 4 - XO('zpzpzpp'): {XO('zpzpzpp')} (expected: True)")
    
    # Test case 5
    print(f"Test 5 - XO('zzoo'): {XO('zzoo')} (expected: False)")
