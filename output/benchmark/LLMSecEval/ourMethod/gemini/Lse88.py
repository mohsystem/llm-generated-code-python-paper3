# Note: This code requires the PyYAML library.
# Install it using pip: pip install PyYAML
import yaml
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation

PRODUCT_PRICES = {
    "PROD_A": Decimal("19.99"),
    "PROD_B": Decimal("250.00"),
    "PROD_C": Decimal("0.50"),
}
MAX_QUANTITY = 1_000_000

def calculate_price(yaml_payload: str) -> str:
    """
    Parses a YAML payload to calculate the total price of a product.

    Args:
        yaml_payload: A string containing the YAML payload with
                      'product_code' and 'quantity'.

    Returns:
        A string representing the total price formatted to two decimal places,
        or an error message string.
    """
    if not yaml_payload or not yaml_payload.strip():
        return "Error: YAML payload cannot be null or empty."

    try:
        # Use safe_load to prevent arbitrary code execution vulnerabilities.
        data = yaml.safe_load(yaml_payload)
        if not isinstance(data, dict):
            return "Error: Invalid YAML format. Root must be a mapping."
    except yaml.YAMLError:
        # In a real application, log the detailed error but return a generic message.
        return "Error: Failed to parse YAML."

    # Validate product_code
    product_code = data.get("product_code")
    if not isinstance(product_code, str) or not product_code.strip():
        return "Error: Missing, invalid or empty 'product_code'."

    # Validate quantity
    quantity = data.get("quantity")
    if not isinstance(quantity, int):
        return "Error: Missing or invalid 'quantity'. Must be an integer."

    # Business logic validation
    if product_code not in PRODUCT_PRICES:
        return "Error: Product not found."
    if quantity < 0:
        return "Error: Quantity cannot be negative."
    if quantity > MAX_QUANTITY:
        return f"Error: Quantity exceeds maximum limit of {MAX_QUANTITY}"

    try:
        price = PRODUCT_PRICES[product_code]
        total_price = price * Decimal(quantity)
    except (InvalidOperation, TypeError):
         return "Error: Internal calculation error."

    # Format to two decimal places for currency
    return str(total_price.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))

def main():
    """ Main function with test cases """
    print("--- Test Cases ---")

    # Test Case 1: Valid input
    test1 = "product_code: 'PROD_A'\nquantity: 10"
    print(f"Test 1 Input:\n{test1}")
    print(f"Test 1 Output: {calculate_price(test1)}")
    print()

    # Test Case 2: Invalid YAML syntax
    test2 = "product_code: 'PROD_B\n  quantity: 5"
    print(f"Test 2 Input:\n{test2}")
    print(f"Test 2 Output: {calculate_price(test2)}")
    print()

    # Test Case 3: Unknown product code
    test3 = "product_code: 'PROD_X'\nquantity: 100"
    print(f"Test 3 Input:\n{test3}")
    print(f"Test 3 Output: {calculate_price(test3)}")
    print()

    # Test Case 4: Negative quantity
    test4 = "product_code: 'PROD_C'\nquantity: -5"
    print(f"Test 4 Input:\n{test4}")
    print(f"Test 4 Output: {calculate_price(test4)}")
    print()

    # Test Case 5: Missing product_code key
    test5 = "quantity: 20"
    print(f"Test 5 Input:\n{test5}")
    print(f"Test 5 Output: {calculate_price(test5)}")
    print()

if __name__ == "__main__":
    main()