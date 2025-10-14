# A dictionary to act as our in-memory product table.
# Using a constant-style name to indicate it should not be modified.
PRODUCT_TABLE = {
    101: {"name": "Laptop", "price": 1200.50},
    102: {"name": "Mouse", "price": 25.00},
    103: {"name": "Keyboard", "price": 75.75},
    104: {"name": "Monitor", "price": 300.00},
    105: {"name": "Webcam", "price": 50.25},
}

def get_product_details(product_id: int) -> str:
    """
    Inquires the product table for a product's details based on its ID.

    Args:
        product_id: The integer ID of the product to look up.

    Returns:
        A string containing the product details or a "not found" message.
    """
    # Use the .get() method which safely returns None if the key is not found,
    # preventing a KeyError.
    product = PRODUCT_TABLE.get(product_id)

    if product:
        # Using an f-string for safe and readable string formatting.
        return f"Product ID: {product_id}, Name: {product['name']}, Price: ${product['price']:.2f}"
    else:
        return f"Product with ID {product_id} not found."

# Main execution block with test cases
if __name__ == "__main__":
    print("--- Product Inquiry System ---")
    
    # Test cases
    test_cases = [101, 104, 105, 999, 0]

    for i, pid in enumerate(test_cases, 1):
        print(f"Test Case {i}: Searching for product ID {pid}")
        result = get_product_details(pid)
        print(f"Result: {result}\n")