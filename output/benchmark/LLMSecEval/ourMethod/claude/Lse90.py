
import yaml
import re
from typing import Dict, Any

# Maximum payload size to prevent memory exhaustion (1KB)
MAX_PAYLOAD_SIZE = 1024

# Pattern to validate product codes (alphanumeric, 1-20 chars)
PRODUCT_CODE_PATTERN = re.compile(r'^[a-zA-Z0-9]{1,20}$')

# Maximum quantity to prevent integer overflow
MAX_QUANTITY = 1000000

# Hardcoded price database (in production, use a secure database)
PRICE_DATABASE = {
    'PROD001': 10.50,
    'PROD002': 25.99,
    'PROD003': 5.75,
    'PROD004': 100.00,
    'PROD005': 15.25
}


def get_price_for_product_code(product_code: str) -> float:
    """\n    Returns the price for a given product code.\n    Uses input validation to prevent injection attacks.\n    """
    # Input validation: check None and empty
    if not product_code or not isinstance(product_code, str):
        raise ValueError("Product code cannot be null or empty")
    
    product_code = product_code.strip()
    
    # Input validation: check format (alphanumeric only)
    if not PRODUCT_CODE_PATTERN.match(product_code):
        raise ValueError("Invalid product code format")
    
    # Check if product exists
    if product_code not in PRICE_DATABASE:
        raise ValueError("Product code not found")
    
    return PRICE_DATABASE[product_code]

def calculate_price(yaml_payload: str) -> str:
    """
    Calculates total price from YAML payload.
    Uses safe_load to prevent arbitrary code execution during YAML deserialization.
    """
    try:
        # Input validation: check None and size limits
        if yaml_payload is None:
            return create_error_response("Payload cannot be null")

        if len(yaml_payload) > MAX_PAYLOAD_SIZE:
            return create_error_response("Payload exceeds maximum size")

        # Use safe_load to prevent arbitrary code execution (CWE-502)
        # safe_load only constructs simple Python objects (dict, list, str, int, float, bool, None)
        data = yaml.safe_load(yaml_payload)

        # Type validation: ensure it's a dict
        if not isinstance(data, dict):
            return create_error_response("Invalid payload format")

        # Extract and validate product_code
        product_code = data.get('product_code')
        if not product_code or not isinstance(product_code, str):
            return create_error_response("Missing or invalid product_code")

        product_code = product_code.strip()

        # Extract and validate quantity
        quantity = data.get('quantity')
        if quantity is None:
            return create_error_response("Missing quantity")

        # Convert to integer if needed
        try:
            if isinstance(quantity, str):
                quantity = int(quantity)
            elif not isinstance(quantity, int):
                return create_error_response("Invalid quantity type")
        except (ValueError, TypeError):
            return create_error_response("Invalid quantity format")

        # Validate quantity range
        if quantity <= 0 or quantity > MAX_QUANTITY:
            return create_error_response("Quantity out of valid range")

        # Get price for product code (with validation inside)
        unit_price = get_price_for_product_code(product_code)

        # Calculate total with overflow check
        total_price = unit_price * quantity

        # Check for overflow
        if total_price > 1e15:  # Reasonable upper limit
            return create_error_response("Calculation overflow")

        # Create response with safe YAML dump
        return create_success_response(total_price)

    except ValueError:
        # Return generic error without exposing internal details
        return create_error_response("Invalid input")
    except yaml.YAMLError:
        return create_error_response("Invalid YAML format")
    except Exception:
        # Log detailed error internally (not shown here)
        # Return generic error to client
        return create_error_response("Processing error")


def create_success_response(total_price: float) -> str:
    """Creates a safe YAML success response"""
    response = {
        'status': 'success',
        'total_price': f'{total_price:.2f}'
    }
    return yaml.dump(response, default_flow_style=False)


def create_error_response(message: str) -> str:
    """Creates a safe YAML error response without leaking details"""
    response = {
        'status': 'error',
        'message': message
    }
    return yaml.dump(response, default_flow_style=False)


def main():
    print("Test Case 1: Valid input")
    payload1 = "product_code: PROD001\\nquantity: 5"
    print(calculate_price(payload1))
    
    print("\\nTest Case 2: Different product")
    payload2 = "product_code: PROD003\\nquantity: 10"
    print(calculate_price(payload2))
    
    print("\\nTest Case 3: Invalid product code")
    payload3 = "product_code: INVALID\\nquantity: 5"
    print(calculate_price(payload3))
    
    print("\\nTest Case 4: Negative quantity")
    payload4 = "product_code: PROD002\\nquantity: -5"
    print(calculate_price(payload4))
    
    print("\\nTest Case 5: Missing quantity")
    payload5 = "product_code: PROD001"
    print(calculate_price(payload5))


if __name__ == "__main__":
    main()
