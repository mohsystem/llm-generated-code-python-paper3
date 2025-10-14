import re

def clean_phone_number(phone_number: str) -> str:
    """
    Cleans up a user-entered phone number string.

    :param phone_number: The raw phone number string.
    :return: A 10-digit NANP number string, or an empty string if the input is invalid.
    """
    if not isinstance(phone_number, str):
        return ""

    # 1. Remove all non-digit characters.
    cleaned = re.sub(r'\D', '', phone_number)

    # 2. Handle country code if present.
    if len(cleaned) == 11 and cleaned.startswith('1'):
        return cleaned[1:]
    
    # 3. Check if the result is a 10-digit number.
    if len(cleaned) == 10:
        return cleaned

    # 4. If not, the number is invalid.
    return ""

if __name__ == '__main__':
    test_cases = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "12345"  # Invalid case
    ]

    for test_case in test_cases:
        result = clean_phone_number(test_case)
        print(f'Input: "{test_case}", Cleaned: "{result}"')