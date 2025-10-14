import sys

def create_phone_number(numbers):
    """
    Formats a list of 10 integers (0-9) into a phone number string.
    
    Args:
        numbers: A list of 10 integers.
        
    Returns:
        A formatted string like "(123) 456-7890".
        
    Raises:
        ValueError: if the input is invalid.
    """
    # Security: Validate input type and length.
    if not isinstance(numbers, list) or len(numbers) != 10:
        raise ValueError("Input must be a list of exactly 10 integers.")

    # Security: Validate that all elements are single-digit integers.
    if not all(isinstance(n, int) and 0 <= n <= 9 for n in numbers):
        raise ValueError("All elements in the list must be integers between 0 and 9.")
        
    return "({}{}{}) {}{}{}-{}{}{}{}".format(*numbers)


# Main execution block with 5 test cases
if __name__ == "__main__":
    # Test Case 1: Valid input
    case1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    print(f"Test Case 1: {create_phone_number(case1)}")

    # Test Case 2: Valid input with zeros
    case2 = [0, 0, 0, 1, 1, 1, 2, 2, 2, 2]
    print(f"Test Case 2: {create_phone_number(case2)}")

    # Test Case 3: Invalid length (too long)
    try:
        case3 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]
        print(f"Test Case 3: {create_phone_number(case3)}")
    except ValueError as e:
        print(f"Test Case 3: Caught expected exception - {e}", file=sys.stderr)

    # Test Case 4: Invalid number (out of range)
    try:
        case4 = [1, 2, 3, 4, -5, 6, 7, 8, 9, 0]
        print(f"Test Case 4: {create_phone_number(case4)}")
    except ValueError as e:
        print(f"Test Case 4: Caught expected exception - {e}", file=sys.stderr)

    # Test Case 5: Invalid input type
    try:
        case5 = "1234567890"
        print(f"Test Case 5: {create_phone_number(case5)}")
    except ValueError as e:
        print(f"Test Case 5: Caught expected exception - {e}", file=sys.stderr)