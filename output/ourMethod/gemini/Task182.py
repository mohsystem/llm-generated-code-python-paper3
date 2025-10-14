import re

def clean_phone_number(phone_number: str) -> str:
    """
    Cleans up a user-entered phone number string by removing punctuation
    and the NANP country code (1) if present.

    :param phone_number: The raw phone number string.
    :return: A 10-digit phone number string if the input is a valid NANP number,
             otherwise an empty string.
    """
    if not isinstance(phone_number, str):
        return ""
        
    # Keep only digits
    digits = "".join(filter(str.isdigit, phone_number))

    # Check length and country code
    if len(digits) == 11:
        if digits.startswith('1'):
            return digits[1:]
    elif len(digits) == 10:
        return digits

    # Return empty string for invalid lengths or invalid country codes
    return ""

if __name__ == '__main__':
    test_cases = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "2 (123) 456-7890" # Invalid country code
    ]

    for test_case in test_cases:
        cleaned_number = clean_phone_number(test_case)
        print(f'Original: "{test_case}", Cleaned: "{cleaned_number}"')