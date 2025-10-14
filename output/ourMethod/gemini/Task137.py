import typing

# Product table represented as a dictionary.
# Keys are product IDs, values are tuples of (name, price).
PRODUCT_TABLE: typing.Dict[str, typing.Tuple[str, float]] = {
    "A123": ("Laptop", 999.99),
    "B456": ("Mouse", 25.50),
    "C789": ("Keyboard", 75.00),
}

def get_product_details(product_id: typing.Optional[str]) -> str:
    """
    Inquires the product table for product details.

    Args:
        product_id: The ID of the product to look for.

    Returns:
        A string with product details or an error message.
    """
    # Rule #3: Validate input. Treat all inputs as untrusted.
    # Check type, non-existence, and emptiness.
    if not isinstance(product_id, str) or not product_id.strip():
        return "Error: Product ID must be a non-empty string."

    # Rule #1: Use safe formatting (f-strings).
    product = PRODUCT_TABLE.get(product_id)

    if product:
        name, price = product
        return f"Product: {name}, Price: ${price:.2f}"
    else:
        # Sanitize output
        sanitized_id = product_id[:50] # Limit length
        return f"Product with ID '{sanitized_id}' not found."

def main():
    """Main function with test cases."""
    print("--- Product Inquiry System ---")

    test_cases: typing.List[typing.Optional[str]] = [
        "A123",       # Test Case 1: Valid, existing product ID
        "C789",       # Test Case 2: Another valid, existing product ID
        "X999",       # Test Case 3: Valid format, but non-existent ID
        "",           # Test Case 4: Invalid empty string
        None          # Test Case 5: Invalid None input
    ]

    for i, test_input in enumerate(test_cases, 1):
        print(f"Test Case {i} (Input: \"{test_input}\"):")
        result = get_product_details(test_input)
        print(f"  Result: {result}\n")

if __name__ == "__main__":
    main()