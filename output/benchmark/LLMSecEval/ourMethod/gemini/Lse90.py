# The PyYAML library is required. Install it using: pip install PyYAML
import yaml
import sys

PRODUCT_PRICES = {
    "PROD123": 10.50,
    "PROD456": 25.00,
    "PROD789": 5.75,
}

def get_price_for_product_code(product_code: str) -> float:
    """
    Returns the price for a given product code.
    Raises ValueError if the product code is not found.
    """
    price = PRODUCT_PRICES.get(product_code)
    if price is None:
        raise ValueError(f"Invalid product code: {product_code}")
    return price

def calculate_price(yaml_payload: str) -> str:
    """
    A web route that calculates the total price from a YAML payload.
    Returns a YAML string with the total price or an error message.
    """
    try:
        # Rule#1: Ensure all input is validated
        if not isinstance(yaml_payload, str) or not yaml_payload.strip():
            raise ValueError("YAML payload must be a non-empty string.")

        # Limit input size to prevent DoS attacks. A web framework would typically
        # handle this, but we simulate it here.
        MAX_PAYLOAD_SIZE = 5 * 1024 * 1024 # 5 MB
        if len(yaml_payload.encode('utf-8')) > MAX_PAYLOAD_SIZE:
            raise ValueError("Payload size exceeds limit.")

        # Rule#2: Use safer alternatives. yaml.safe_load is used to prevent
        # arbitrary code execution vulnerabilities (CWE-502).
        data = yaml.safe_load(yaml_payload)

        if not isinstance(data, dict):
            raise ValueError("Invalid YAML format: root must be a mapping.")

        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if product_code is None:
            raise ValueError("Missing 'product_code' in YAML payload.")
        if not isinstance(product_code, str):
            raise ValueError("'product_code' must be a string.")
        
        if quantity is None:
            raise ValueError("Missing 'quantity' in YAML payload.")
        if not isinstance(quantity, int):
            raise ValueError("'quantity' must be an integer.")
        if quantity <= 0:
            raise ValueError("'quantity' must be positive.")

        price = get_price_for_product_code(product_code)
        total_price = price * quantity

        return yaml.dump({"total_price": total_price})

    except (ValueError, yaml.YAMLError) as e:
        # Rule#5: Return generic messages to callers
        return yaml.dump({"error": str(e)})
    except Exception:
        # Catch any other unexpected exception
        return yaml.dump({"error": "An unexpected error occurred."})

if __name__ == "__main__":
    test_cases = [
        # Test Case 1: Valid input
        "product_code: PROD123\nquantity: 2",
        # Test Case 2: Invalid product code
        "product_code: UNKNOWN\nquantity: 1",
        # Test Case 3: Invalid quantity (negative)
        "product_code: PROD456\nquantity: -5",
        # Test Case 4: Malformed YAML
        "product_code: PROD123, quantity: 2",
        # Test Case 5: Missing key
        "product_code: PROD789"
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Input YAML:\n---\n{test_case}\n---")
        result = calculate_price(test_case)
        print(f"Output YAML:\n{result}")