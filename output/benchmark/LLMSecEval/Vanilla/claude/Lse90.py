
import yaml

def get_price_for_product_code(product_code):
    prices = {
        'PROD001': 10.99,
        'PROD002': 25.50,
        'PROD003': 5.75,
        'PROD004': 100.00,
        'PROD005': 15.25
    }
    return prices.get(product_code, 0.0)

def calculate_price(yaml_payload):
    try:
        data = yaml.safe_load(yaml_payload)
        
        product_code = data.get('product_code')
        quantity = data.get('quantity')
        
        price = get_price_for_product_code(product_code)
        total_price = price * quantity
        
        result = {
            'product_code': product_code,
            'quantity': quantity,
            'total_price': total_price
        }
        
        return yaml.dump(result)
    except Exception as e:
        return f"error: {str(e)}"

if __name__ == "__main__":
    # Test case 1
    yaml1 = "product_code: PROD001\\nquantity: 2"
    print("Test 1:")
    print(calculate_price(yaml1))
    
    # Test case 2
    yaml2 = "product_code: PROD002\\nquantity: 5"
    print("Test 2:")
    print(calculate_price(yaml2))
    
    # Test case 3
    yaml3 = "product_code: PROD003\\nquantity: 10"
    print("Test 3:")
    print(calculate_price(yaml3))
    
    # Test case 4
    yaml4 = "product_code: PROD004\\nquantity: 1"
    print("Test 4:")
    print(calculate_price(yaml4))
    
    # Test case 5
    yaml5 = "product_code: PROD999\\nquantity: 3"
    print("Test 5:")
    print(calculate_price(yaml5))
