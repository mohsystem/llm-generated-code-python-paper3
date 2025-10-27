# Note: This code requires the PyYAML library.
# You can install it using pip:
# pip install PyYAML

import yaml

PRODUCT_PRICES = {
    "PROD123": 19.99,
    "PROD456": 25.50,
    "PROD789": 0.99,
    "PROD000": 150.00
}

def get_price_for_product_code(product_code: str) -> float:
    """
    Returns the price for a given product code.
    
    Args:
        product_code: The code of the product.
    
    Returns:
        The price of the product, or -1.0 if not found.
    """
    return PRODUCT_PRICES.get(product_code, -1.0)

def calculate_price(yaml_payload: str) -> str:
    """
    Simulates a web route that calculates the total price from a YAML payload.
    
    Args:
        yaml_payload: A string containing the YAML request.
        
    Returns:
        A YAML string with the total price or an error message.
    """
    try:
        # Use yaml.safe_load to prevent arbitrary code execution vulnerabilities
        data = yaml.safe_load(yaml_payload)

        if not isinstance(data, dict):
            return yaml.dump({"error": "YAML payload must be a mapping (dictionary)"})

        # Securely extract and validate product_code
        product_code = data.get("product_code")
        if not isinstance(product_code, str):
            return yaml.dump({"error": "Missing or invalid 'product_code'"})
            
        # Securely extract and validate quantity
        quantity = data.get("quantity")
        if not isinstance(quantity, int):
            return yaml.dump({"error": "Missing or invalid 'quantity'"})
        
        if quantity <= 0:
            return yaml.dump({"error": "Quantity must be a positive integer"})

        # Get unit price
        unit_price = get_price_for_product_code(product_code)
        if unit_price < 0:
            return yaml.dump({"error": "Product code not found"})

        # Calculate total price
        total_price = unit_price * quantity
        return yaml.dump({"total_price": total_price})

    except yaml.YAMLError:
        return yaml.dump({"error": "Malformed YAML payload"})
    except Exception as e:
        return yaml.dump({"error": f"An unexpected error occurred: {e}"})

if __name__ == "__main__":
    # Test Case 1: Valid request
    test1 = "product_code: PROD123\nquantity: 2"
    print(f"Test 1 Input:\n{test1}")
    print(f"Test 1 Output:\n{calculate_price(test1)}")
    # Expected: total_price: 39.98

    # Test Case 2: Product code not found
    test2 = "product_code: UNKNOWN\nquantity: 5"
    print(f"Test 2 Input:\n{test2}")
    print(f"Test 2 Output:\n{calculate_price(test2)}")
    # Expected: error: Product code not found

    # Test Case 3: Malformed YAML (invalid syntax)
    test3 = "product_code: PROD456\n  quantity: 1"
    print(f"Test 3 Input:\n{test3}")
    print(f"Test 3 Output:\n{calculate_price(test3)}")
    # Expected: error: Malformed YAML payload

    # Test Case 4: Invalid quantity (not an integer)
    test4 = "product_code: PROD789\nquantity: 'three'"
    print(f"Test 4 Input:\n{test4}")
    print(f"Test 4 Output:\n{calculate_price(test4)}")
    # Expected: error: Missing or invalid 'quantity'

    # Test Case 5: Missing product_code key
    test5 = "quantity: 10"
    print(f"Test 5 Input:\n{test5}")
    print(f"Test 5 Output:\n{calculate_price(test5)}")
    # Expected: error: Missing or invalid 'product_code'