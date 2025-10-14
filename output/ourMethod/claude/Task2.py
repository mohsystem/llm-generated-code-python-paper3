
from typing import List

def create_phone_number(numbers: List[int]) -> str:
    """\n    Formats an array of 10 integers (0-9) into a phone number string.\n    \n    Args:\n        numbers: List of exactly 10 integers between 0 and 9\n        \n    Returns:\n        Formatted phone number string in format (XXX) XXX-XXXX\n        \n    Raises:\n        ValueError: If input validation fails\n    """
    # Validate input is not None
    if numbers is None:
        raise ValueError("Input list cannot be None")
    
    # Validate list length
    if len(numbers) != 10:
        raise ValueError("Input list must contain exactly 10 elements")
    
    # Validate each element is an integer between 0 and 9
    for i, num in enumerate(numbers):
        if not isinstance(num, int):
            raise ValueError(f"Element at index {i} must be an integer")
        if num < 0 or num > 9:
            raise ValueError(f"Element at index {i} must be between 0 and 9")
    
    # Format phone number using constant format string
    return "({}{}{}) {}{}{}-{}{}{}{}".format(
        numbers[0], numbers[1], numbers[2],
        numbers[3], numbers[4], numbers[5],
        numbers[6], numbers[7], numbers[8], numbers[9]
    )

if __name__ == "__main__":
    # Test case 1: Standard example
    test1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    print(create_phone_number(test1))
    
    # Test case 2: All zeros
    test2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    print(create_phone_number(test2))
    
    # Test case 3: All nines
    test3 = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
    print(create_phone_number(test3))
    
    # Test case 4: Mixed digits
    test4 = [5, 5, 5, 1, 2, 3, 4, 5, 6, 7]
    print(create_phone_number(test4))
    
    # Test case 5: Another pattern
    test5 = [8, 6, 7, 5, 3, 0, 9, 1, 2, 3]
    print(create_phone_number(test5))
