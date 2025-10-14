def clean_phone_number(phone_number: str) -> str:
    """
    Cleans up user-entered phone numbers.
    Removes punctuation and the country code (1) if present.
    Returns a 10-digit phone number string, or an empty string if the input is not a valid NANP number.
    """
    # Keep only digit characters
    digits = "".join(filter(str.isdigit, phone_number))

    # Check for country code and length
    if len(digits) == 11:
        if digits.startswith("1"):
            return digits[1:]
    elif len(digits) == 10:
        return digits
    
    # Return empty for invalid formats
    return ""

if __name__ == "__main__":
    test_cases = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "(223) 456-7890"
    ]

    for test_case in test_cases:
        print(f'Input: "{test_case}", Output: "{clean_phone_number(test_case)}"')