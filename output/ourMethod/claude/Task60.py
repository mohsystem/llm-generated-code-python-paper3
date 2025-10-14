
from typing import List


def expanded_form(num: int) -> str:
    """Convert a number to its expanded form as a string."""
    # Input validation: ensure num is a positive integer
    if not isinstance(num, int):
        raise TypeError("Input must be an integer")
    
    if num <= 0:
        raise ValueError("Number must be greater than 0")
    
    # Prevent overflow by checking reasonable bounds
    if num > 10**15:
        raise ValueError("Number too large")
    
    num_str: str = str(num)
    parts: List[str] = []
    length: int = len(num_str)
    
    for i, digit in enumerate(num_str):
        if digit != '0':
            power_of_ten: int = length - i - 1
            expanded_value: int = int(digit) * (10 ** power_of_ten)
            parts.append(str(expanded_value))
    
    return " + ".join(parts)


def main() -> None:
    """Run test cases."""
    # Test case 1
    print(expanded_form(12))
    
    # Test case 2
    print(expanded_form(42))
    
    # Test case 3
    print(expanded_form(70304))
    
    # Test case 4
    print(expanded_form(9))
    
    # Test case 5
    print(expanded_form(123456))


if __name__ == "__main__":
    main()
