import yaml

# A mock database of product prices
PRODUCT_PRICES = {
    "PROD001": 10.50,
    "PROD002": 25.00,
    "PROD003": 5.75,
    "PROD004": 150.00,
}

def get_price_for_product_code(product_code: str) -> float:
    """Returns the price for a given product code."""
    return PRODUCT_PRICES.get(product_code, -1.0)

def calculate_price(yaml_payload: str) -> str:
    """
    Simulates a web route that takes a YAML payload, calculates the total price,
    and returns the result as a YAML payload.

    This function uses yaml.safe_load() to prevent arbitrary code execution,
    which is a critical security measure against unsafe YAML deserialization.
    """
    try:
        # Use safe_load to parse the YAML. This is crucial for security.
        data = yaml.safe_load(yaml_payload)
        
        if not isinstance(data, dict):
            raise ValueError("Payload must be a YAML mapping.")

        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if not product_code or not isinstance(product_code, str):
            result = {"error": "Invalid or missing 'product_code'."}
        elif not quantity or not isinstance(quantity, int):
            result = {"error": "Invalid or missing 'quantity'."}
        elif quantity <= 0:
            result = {"error": "Quantity must be positive."}
        else:
            price = get_price_for_product_code(product_code)
            if price < 0:
                result = {"error": "Product code not found."}
            else:
                total_price = price * quantity
                result = {"total_price": total_price}

    except (yaml.YAMLError, ValueError) as e:
        result = {"error": f"Failed to parse YAML payload: {e}"}
    except Exception:
        result = {"error": "An unexpected error occurred."}

    return yaml.dump(result)

def main():
    """Main function with test cases."""
    test_cases = [
        # Test Case 1: Valid request
        "product_code: PROD001\nquantity: 10",
        # Test Case 2: Another valid request
        "product_code: PROD004\nquantity: 2",
        # Test Case 3: Product code not found
        "product_code: PROD999\nquantity: 5",
        # Test Case 4: Invalid payload (missing quantity)
        "product_code: PROD002",
        # Test Case 5: Malformed YAML
        "product_code: PROD003\n  quantity: 1" # incorrect indentation
    ]
    
    print("--- Running Python Test Cases ---")
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input:\n---\n{test_case}\n---")
        result = calculate_price(test_case)
        print(f"Output:\n{result}")

if __name__ == "__main__":
    main()