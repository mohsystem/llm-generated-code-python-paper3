def largest_product(input_str: str, span: int) -> int:
    if input_str is None:
        raise ValueError("Input cannot be None.")
    if span < 0:
        raise ValueError("Span cannot be negative.")
    if span == 0:
        return 1
    if span > len(input_str):
        raise ValueError("Span cannot exceed input length.")
    if any(ch < '0' or ch > '9' for ch in input_str):
        raise ValueError("Input must contain only digits.")

    n = len(input_str)
    digits = [ord(c) - ord('0') for c in input_str]

    zeros = 0
    product = 1
    product_valid = True

    for i in range(span):
        d = digits[i]
        if d == 0:
            zeros += 1
            product_valid = False
        else:
            product *= d

    max_prod = product if zeros == 0 else 0

    for i in range(span, n):
        outgoing = digits[i - span]
        incoming = digits[i]

        if outgoing == 0:
            zeros -= 1
            product_valid = False
        elif zeros == 0 and product_valid:
            product //= outgoing

        if incoming == 0:
            zeros += 1
            product_valid = False
        elif zeros == 0 and product_valid:
            product *= incoming

        if zeros == 0 and not product_valid:
            product = 1
            for k in range(i - span + 1, i + 1):
                product *= digits[k]
            product_valid = True

        if zeros == 0 and product > max_prod:
            max_prod = product

    return max_prod


if __name__ == "__main__":
    tests = [
        ("63915", 3),
        ("123456789", 2),
        ("1020304050", 2),
        ("000", 2),
        ("", 0),
    ]
    for s, sp in tests:
        try:
            print(f"Input: {s}, Span: {sp} -> {largest_product(s, sp)}")
        except ValueError as e:
            print(f"Input: {s}, Span: {sp} -> Error: {e}")