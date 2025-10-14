
def clean_phone_number(input_str: str) -> str:
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(input_str, str):
        raise ValueError("Input must be a string")
    
    if len(input_str) > 50:
        raise ValueError("Input too long")
    
    digits = []
    for c in input_str:
        if c.isdigit():
            digits.append(c)
        elif c not in [' ', '-', '.', '(', ')', '+']:
            raise ValueError("Invalid character in phone number")
    
    digit_string = ''.join(digits)
    
    if len(digit_string) == 11:
        if digit_string[0] != '1':
            raise ValueError("Invalid country code")
        digit_string = digit_string[1:]
    elif len(digit_string) != 10:
        raise ValueError("Invalid phone number length")
    
    if len(digit_string) != 10:
        raise ValueError("Phone number must be 10 digits")
    
    area_code = digit_string[0]
    exchange_code = digit_string[3]
    
    if area_code < '2' or area_code > '9':
        raise ValueError("Area code must start with digit 2-9")
    
    if exchange_code < '2' or exchange_code > '9':
        raise ValueError("Exchange code must start with digit 2-9")
    
    return digit_string


def main():
    test_cases = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "(234) 567-8901"
    ]
    
    for test_case in test_cases:
        try:
            result = clean_phone_number(test_case)
            print(f"Input: {test_case} -> Output: {result}")
        except ValueError as e:
            print(f"Input: {test_case} -> Error: {e}")


if __name__ == "__main__":
    main()
