# PyYAML is a third-party library. To run this code, you need to install it:
# pip install PyYAML
import yaml

PRODUCT_PRICES = {
    "PROD1": 10.50,
    "PROD2": 25.00,
    "PROD3": 5.75,
}

def calculate_price(yaml_payload: str) -> str:
    """
    Calculates the total price based on a YAML payload.
    This is a secure implementation that uses yaml.safe_load()
    to prevent arbitrary code execution during deserialization.

    Args:
        yaml_payload: A string containing the YAML payload.
    
    Returns:
        A string representing the total price or an error message.
    """
    try:
        # yaml.safe_load() is the secure way to parse YAML from untrusted sources.
        # It prevents execution of arbitrary code, unlike yaml.load().
        data = yaml.safe_load(yaml_payload)

        if not isinstance(data, dict):
            return "Error: YAML payload must be a dictionary."
        
        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if not product_code or not isinstance(product_code, str):
            return "Error: 'product_code' is missing or not a string."
        
        if quantity is None or not isinstance(quantity, (int, float)):
            return "Error: 'quantity' is missing or not a number."
            
        quantity = int(quantity)
        if quantity <= 0:
            return "Error: Quantity must be positive."

        price = PRODUCT_PRICES.get(product_code)
        if price is None:
            return "Error: Product code not found."

        total_price = price * quantity
        return f"{total_price:.2f}"

    except yaml.YAMLError as e:
        return f"Error: Invalid YAML format. {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred. {e}"

def main():
    test_cases = [
        # Test Case 1: Valid input
        'product_code: "PROD1"\nquantity: 10',
        # Test Case 2: Unknown product code
        'product_code: "PROD99"\nquantity: 5',
        # Test Case 3: Malformed YAML (invalid syntax)
        'product_code: "PROD2" quantity: 2',
        # Test Case 4: Missing 'quantity' key
        'product_code: "PROD3"',
        # Test Case 5: Invalid quantity type
        'product_code: "PROD1"\nquantity: "five"'
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input:\n---\n{test_case}\n---")
        result = calculate_price(test_case)
        print(f"Output: {result}\n")

if __name__ == "__main__":
    main()