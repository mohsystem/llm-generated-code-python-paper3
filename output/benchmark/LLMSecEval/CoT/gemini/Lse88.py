# Note: This code requires the PyYAML library.
# You can install it using pip:
# pip install pyyaml

import yaml

PRODUCT_PRICES = {
    "PROD001": 10.50,
    "PROD002": 25.00,
    "PROD003": 5.75,
}

def calculate_price(yaml_payload: str) -> str:
    """
    Parses a YAML payload, calculates the total price, and returns it as a string.

    Args:
        yaml_payload: A string containing the YAML payload with product_code and quantity.

    Returns:
        A string representing the total price or an error message.
    """
    try:
        # Use yaml.safe_load to prevent arbitrary code execution vulnerabilities.
        data = yaml.safe_load(yaml_payload)

        if not isinstance(data, dict):
            return "Error: YAML payload must be a mapping (dictionary)."

        # Securely extract and validate keys and types
        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if product_code is None or quantity is None:
            return "Error: Missing 'product_code' or 'quantity' in payload."

        if not isinstance(product_code, str):
            return "Error: 'product_code' must be a string."
        
        if not isinstance(quantity, int):
            return "Error: 'quantity' must be an integer."

        # Input validation
        if quantity <= 0:
            return "Error: Quantity must be a positive integer."

        price = PRODUCT_PRICES.get(product_code)
        if price is None:
            return "Error: Product code not found."

        total_price = price * quantity
        
        # Return formatted string
        return f"{total_price:.2f}"

    except yaml.YAMLError as e:
        return f"Error: Invalid YAML format. {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred. {e}"

# Main execution block with test cases
if __name__ == "__main__":
    test_cases = [
        # 1. Valid case
        "product_code: 'PROD002'\nquantity: 3",
        # 2. Product not found
        "product_code: 'PROD999'\nquantity: 1",
        # 3. Invalid YAML format (e.g., using tabs)
        "product_code: 'PROD001'\n\tquantity: 5",
        # 4. Missing key ('quantity')
        "product_code: 'PROD003'",
        # 5. Invalid data type for quantity
        "product_code: 'PROD001'\nquantity: 'two'"
    ]
    
    print("--- Python Test Cases ---")
    for i, test in enumerate(test_cases, 1):
        print(f"Test Case {i}:\nInput:\n---\n{test}\n---")
        result = calculate_price(test)
        print(f"Output: {result}\n")