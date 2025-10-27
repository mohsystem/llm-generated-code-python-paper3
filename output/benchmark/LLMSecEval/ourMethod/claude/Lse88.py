
import yaml
import re
from decimal import Decimal, InvalidOperation
from typing import Optional

# Hardcoded product prices - in production, fetch from secure database
PRODUCT_PRICES = {
    "PROD-001": Decimal("10.50"),
    "PROD-002": Decimal("25.00"),
    "PROD-003": Decimal("5.99"),
    "PROD-004": Decimal("100.00"),
    "PROD-005": Decimal("15.75")
}

# Maximum YAML payload size to prevent DoS (10KB)
MAX_YAML_SIZE = 10240

# Pattern to validate product codes (alphanumeric and hyphens only)
PRODUCT_CODE_PATTERN = re.compile(r'^[a-zA-Z0-9-]{1,50}$')
def calculate_price(yaml_payload: str) -> str:
    """
    Calculates price based on YAML payload.
    Security measures:
    - Input size validation to prevent DoS
    - Safe YAML parsing using safe_load (no arbitrary code execution)
    - Type validation for all extracted values
    - Range validation for quantity
    - Whitelist validation for product codes
    - Overflow prevention using Decimal
    - Generic error messages to prevent information leakage
    """
    try:
        # Validate input is not None or empty
        if not yaml_payload or not yaml_payload.strip():
            return "Error: Invalid request"

        # Validate payload size to prevent DoS attacks
        if len(yaml_payload) > MAX_YAML_SIZE:
            return "Error: Request too large"

        # Parse YAML safely - safe_load prevents code execution
        # and does not resolve external entities
        try:
            data = yaml.safe_load(yaml_payload)
        except yaml.YAMLError:
            # Generic error message - don't leak parsing details
            return "Error: Invalid format"

        # Validate data is a dictionary
        if not isinstance(data, dict):
            return "Error: Invalid format"

        # Validate required fields exist
        if "product_code" not in data or "quantity" not in data:
            return "Error: Missing required fields"

        # Extract and validate product_code
        product_code = data.get("product_code")
        if not isinstance(product_code, str):
            return "Error: Invalid product code type"

        product_code = product_code.strip()

        # Validate product code format against whitelist pattern
        if not PRODUCT_CODE_PATTERN.match(product_code):
            return "Error: Invalid product code format"

        # Extract and validate quantity
        quantity = data.get("quantity")

        # Handle quantity as int or string
        if isinstance(quantity, int):
            qty = quantity
        elif isinstance(quantity, str):
            try:
                qty = int(quantity)
            except ValueError:
                return "Error: Invalid quantity format"
        else:
            return "Error: Invalid quantity type"

        # Validate quantity range (1-10000)
        if qty < 1 or qty > 10000:
            return "Error: Quantity out of range"

        # Check if product exists in catalog
        if product_code not in PRODUCT_PRICES:
            return "Error: Product not found"

        # Calculate total price using Decimal to prevent overflow
        unit_price = PRODUCT_PRICES[product_code]
        total_price = unit_price * Decimal(qty)

        # Return formatted result (2 decimal places)
        return f"{total_price:.2f}"

    except Exception:
        # Generic error - log details securely but don't expose to user
        # In production: log to secure logging system without sensitive data
        return "Error: Processing failed"

def main():
    print("Test Case 1 - Valid request:")
    test1 = "product_code: PROD-001\\nquantity: 5"
    print(f"Input: {test1.replace(chr(10), ' | ')}")
    print(f"Output: {calculate_price(test1)}")
    print()
    
    print("Test Case 2 - Different product:")
    test2 = "product_code: PROD-003\\nquantity: 10"
    print(f"Input: {test2.replace(chr(10), ' | ')}")
    print(f"Output: {calculate_price(test2)}")
    print()
    
    print("Test Case 3 - Invalid product code:")
    test3 = "product_code: INVALID\\nquantity: 2"
    print(f"Input: {test3.replace(chr(10), ' | ')}")
    print(f"Output: {calculate_price(test3)}")
    print()
    
    print("Test Case 4 - Quantity out of range:")
    test4 = "product_code: PROD-002\\nquantity: 20000"
    print(f"Input: {test4.replace(chr(10), ' | ')}")
    print(f"Output: {calculate_price(test4)}")
    print()
    
    print("Test Case 5 - Missing field:")
    test5 = "product_code: PROD-001"
    print(f"Input: {test5}")
    print(f"Output: {calculate_price(test5)}")

if __name__ == "__main__":
    main()
