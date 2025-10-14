import re

def clean_phone_number(input_str: str) -> str:
    """
    Cleans a phone number by removing punctuation and country code.
    Validates the number against NANP rules.

    :param input_str: The raw phone number string.
    :return: A 10-digit clean phone number string.
    :raises ValueError: if the number is invalid.
    """
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string.")

    digits = "".join(re.findall(r'\d', input_str))

    if len(digits) == 11:
        if digits.startswith('1'):
            digits = digits[1:]
        else:
            raise ValueError("11-digit number must start with 1.")
    
    if len(digits) != 10:
        raise ValueError("Number must be 10 digits.")

    # Area code is NXX where N is 2-9
    if digits[0] in ('0', '1'):
        raise ValueError("Area code cannot start with 0 or 1.")
    
    # Exchange code is NXX where N is 2-9
    if digits[3] in ('0', '1'):
        raise ValueError("Exchange code cannot start with 0 or 1.")

    return digits

if __name__ == "__main__":
    test_cases = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "(223) 456-7890",
        # Invalid cases for testing robustness
        "1 (123) 456-7890", # Area code starts with 1
        "(223) 056-7890", # Exchange code starts with 0
        "2 (223) 456-7890", # Invalid 11-digit number
        "(223) 456-789",    # Too short
        "123456789012"      # Too long
    ]

    for test_case in test_cases:
        print(f'Input: "{test_case}" -> ', end="")
        try:
            cleaned = clean_phone_number(test_case)
            print(f'Output: {cleaned}')
        except (ValueError, TypeError) as e:
            print(f'Error: {e}')