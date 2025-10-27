
import yaml

# Product price catalog
PRODUCT_PRICES = {
    'PROD001': 10.99,
    'PROD002': 25.50,
    'PROD003': 5.75,
    'PROD004': 100.00,
    'PROD005': 15.25
}

def calculate_price(yaml_payload):
    try:
        data = yaml.safe_load(yaml_payload)
        
        product_code = data.get('product_code')
        quantity = int(data.get('quantity'))
        
        if product_code not in PRODUCT_PRICES:
            return "Error: Product not found"
        
        price = PRODUCT_PRICES[product_code]
        total_price = price * quantity
        
        return f"{total_price:.2f}"
    except Exception as e:
        return f"Error: Invalid YAML payload - {str(e)}"

if __name__ == "__main__":
    # Test case 1: Valid product with quantity 2
    test1 = "product_code: PROD001\\nquantity: 2"
    print(f"Test 1: {calculate_price(test1)}")
    
    # Test case 2: Valid product with quantity 5
    test2 = "product_code: PROD002\\nquantity: 5"
    print(f"Test 2: {calculate_price(test2)}")
    
    # Test case 3: Valid product with quantity 1
    test3 = "product_code: PROD003\\nquantity: 1"
    print(f"Test 3: {calculate_price(test3)}")
    
    # Test case 4: Invalid product code
    test4 = "product_code: PROD999\\nquantity: 3"
    print(f"Test 4: {calculate_price(test4)}")
    
    # Test case 5: Valid product with large quantity
    test5 = "product_code: PROD004\\nquantity: 10"
    print(f"Test 5: {calculate_price(test5)}")
