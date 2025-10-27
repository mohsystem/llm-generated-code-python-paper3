PRICES = {
    "P101": 10.50,
    "P102": 25.00,
    "P103": 5.75,
}

def calculate_price(yaml_payload):
    """
    Parses a simple YAML string to calculate the total price of a product.

    Args:
        yaml_payload: A string containing product_code and quantity.

    Returns:
        The total price formatted as a string, or an error message.
    """
    try:
        data = {}
        lines = yaml_payload.strip().split('\n')
        for line in lines:
            if ':' not in line:
                continue # Skip malformed lines
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip()
            data[key] = value

        product_code_raw = data.get('product_code')
        quantity_str = data.get('quantity')

        if not product_code_raw or not quantity_str:
            return "Error: Invalid format or missing keys"
            
        product_code = product_code_raw.strip('"') # Remove quotes

        if product_code not in PRICES:
            return "Error: Product not found"

        quantity = int(quantity_str)
        
        unit_price = PRICES[product_code]
        total_price = unit_price * quantity
        
        return f"{total_price:.2f}"

    except ValueError:
        return "Error: Invalid quantity"
    except Exception:
        return "Error: An unexpected error occurred"

def main():
    test_cases = [
        # Test Case 1: Standard valid case
        'product_code: "P101"\nquantity: 5',
        # Test Case 2: Another valid case (different order)
        'quantity: 10\nproduct_code: "P103"',
        # Test Case 3: Product not found
        'product_code: "P999"\nquantity: 2',
        # Test Case 4: Invalid quantity
        'product_code: "P102"\nquantity: abc',
        # Test Case 5: Malformed YAML (no colon on one line)
        'product_code "P101"\nquantity: 3'
    ]

    print("Python Test Cases:")
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input:\n---\n{test_case}\n---")
        result = calculate_price(test_case)
        print(f"Output: {result}\n")

if __name__ == "__main__":
    main()