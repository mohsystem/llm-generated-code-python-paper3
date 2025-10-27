# Note: This code requires the PyYAML library.
# You can install it using: pip install pyyaml
import yaml

# In-memory database of product prices
PRICE_MAP = {
    "P101": 10.50,
    "P202": 25.00,
    "P303": 5.75
}

def get_price_for_product_code(product_code):
    """
    Returns the price for a given product code.
    
    Args:
        product_code: The code of the product.
    
    Returns:
        The price of the product, or 0.0 if not found.
    """
    return PRICE_MAP.get(product_code, 0.0)

def calculate_price(yaml_payload):
    """
    Simulates a web route that calculates the total price from a YAML payload.
    
    Args:
        yaml_payload: A string in YAML format containing product_code and quantity.
    
    Returns:
        A YAML string containing the total_price.
    """
    try:
        # Load the YAML payload into a dictionary
        data = yaml.safe_load(yaml_payload)
        if not isinstance(data, dict):
            data = {} # Handle empty or invalid YAML
            
        # Extract the product code and quantity
        product_code = data.get("product_code")
        quantity = int(data.get("quantity", 0))
        
        # Calculate the total price
        price_per_unit = get_price_for_product_code(product_code)
        total_price = price_per_unit * quantity
        
        # Format the result as a YAML payload
        result = {"total_price": round(total_price, 2)}
        return yaml.dump(result)
        
    except (yaml.YAMLError, ValueError, TypeError):
        # Handle errors in parsing or data types
        result = {"total_price": 0.0}
        return yaml.dump(result)

def main():
    """Main function to run test cases."""
    test_cases = [
        "product_code: P101\nquantity: 5",    # Expected: 52.50
        "product_code: P202\nquantity: 1",    # Expected: 25.00
        "product_code: P303\nquantity: 100",  # Expected: 575.00
        "product_code: P999\nquantity: 10",   # Expected: 0.0 (product not found)
        "product_code: P101\nquantity: 0"     # Expected: 0.0
    ]
    
    for i, test in enumerate(test_cases):
        print(f"--- Test Case {i+1} ---")
        print(f"Input YAML:\n---\n{test}\n---")
        output_yaml = calculate_price(test)
        print(f"Output YAML:\n{output_yaml}")

if __name__ == "__main__":
    main()