from typing import List

def expanded_form(num: int) -> str:
    """
    Converts a positive integer into its expanded form string.
    For example: 70304 becomes "70000 + 300 + 4".

    Args:
        num: The positive integer to expand. Must be greater than 0.
    
    Returns:
        The expanded form of the number as a string.
    """
    if not isinstance(num, int) or num <= 0:
        # As per prompt, numbers are whole and > 0. Handle defensively.
        return ""

    s = str(num)
    parts: List[str] = []

    for i, digit in enumerate(s):
        if digit != '0':
            num_zeros = len(s) - 1 - i
            part = digit + '0' * num_zeros
            parts.append(part)

    return " + ".join(parts)

if __name__ == "__main__":
    test_cases = [12, 42, 70304, 9000000, 1]
    for test_case in test_cases:
        print(f'{test_case} -> "{expanded_form(test_case)}"')