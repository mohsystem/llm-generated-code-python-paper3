# In-memory "database" of products. In a real application, this would be
# a database, but for this example, a dictionary is safe from injection.
_PRODUCT_TABLE = {
    "PROD101": {"name": "Laptop", "price": 999.99, "description": "High-performance laptop"},
    "PROD102": {"name": "Mouse", "price": 25.50, "description": "Ergonomic wireless mouse"},
    "PROD103": {"name": "Keyboard", "price": 75.00, "description": "Mechanical gaming keyboard"},
    "PROD104": {"name": "Monitor", "price": 300.00, "description": "27-inch 4K UHD monitor"},
}

def get_product_details(product_id):
    """
    Inquires the product table for product details in a secure manner.
    This function is secure because:
    1. It validates the input type and content, rejecting non-strings and empty strings.
    2. It uses dictionary lookups (.get()), which are not vulnerable to injection attacks.
    3. It handles missing keys gracefully, returning a clear message.

    Args:
        product_id: The ID of the product to look up.

    Returns:
        A string with product details or an error message.
    """
    # 1. Input Validation: Check for non-string, None, or empty/whitespace-only strings.
    if not isinstance(product_id, str) or not product_id.strip():
        return "Error: Product ID cannot be null or empty."

    # 2. Data Lookup: Safely look up the product in the dictionary.
    product = _PRODUCT_TABLE.get(product_id)

    # 3. Result Handling: Format the output or return a 'not found' message.
    if product:
        return (f"Name: {product['name']}, Price: {product['price']:.2f}, "
                f"Description: {product['description']}")
    else:
        return "Product not found."

def main():
    """Main function with test cases."""
    print("--- Product Inquiry System ---")

    test_cases = {
        "Test Case 1 (Valid)": "PROD101",
        "Test Case 2 (Valid)": "PROD103",
        "Test Case 3 (Non-existent)": "PROD999",
        "Test Case 4 (Whitespace)": "   ",
        "Test Case 5 (None)": None,
    }

    for description, test_id in test_cases.items():
        print(f"--- {description} ---")
        print(f"Querying for ID: '{test_id}'")
        result = get_product_details(test_id)
        print(f"Result: {result}\n")

if __name__ == "__main__":
    main()