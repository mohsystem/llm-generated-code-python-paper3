
import yaml
from yaml import SafeLoader

PRODUCT_PRICES = {
    'PROD001': 10.50,
    'PROD002': 25.00,
    'PROD003': 15.75,
    'PROD004': 30.00,
    'PROD005': 5.99
}

def calculate_price(yaml_payload):
    try:
        # Use SafeLoader to prevent code execution vulnerabilities
        data = yaml.load(yaml_payload, Loader=SafeLoader)
        
        # Validate required fields exist
        if not isinstance(data, dict) or 'product_code' not in data or 'quantity' not in data:
            return "Error: Missing required fields"
        
        product_code = str(data['product_code']).strip()
        
        # Validate product code
        if product_code not in PRODUCT_PRICES:
            return "Error: Invalid product code"
        
        # Validate quantity
        try:
            quantity = int(data['quantity'])
            if quantity <= 0 or quantity > 10000:
                return "Error: Quantity must be between 1 and 10000"
        except (ValueError, TypeError):
            return "Error: Invalid quantity format"
        
        # Calculate total price
        price = PRODUCT_PRICES[product_code]
        total_price = price * quantity
        
        return f"{total_price:.2f}"
        
    except yaml.YAMLError:
        return "Error: Invalid YAML format"
    except Exception:
        return "Error: Processing failed"

if __name__ == "__main__":
    # Test case 1: Valid input
    test1 = "product_code: PROD001\\nquantity: 5"
    print(f"Test 1: {calculate_price(test1)}")
    
    # Test case 2: Different product
    test2 = "product_code: PROD003\\nquantity: 10"
    print(f"Test 2: {calculate_price(test2)}")
    
    # Test case 3: Invalid product code
    test3 = "product_code: INVALID\\nquantity: 3"
    print(f"Test 3: {calculate_price(test3)}")
    
    # Test case 4: Invalid quantity
    test4 = "product_code: PROD002\\nquantity: -5"
    print(f"Test 4: {calculate_price(test4)}")
    
    # Test case 5: Missing fields
    test5 = "product_code: PROD001"
    print(f"Test 5: {calculate_price(test5)}")
