
import yaml

class Lse88:
    PRODUCT_PRICES = {
        'PROD001': 10.50,
        'PROD002': 25.99,
        'PROD003': 5.75,
        'PROD004': 100.00,
        'PROD005': 15.25
    }
    
    @staticmethod
    def calculate_price(yaml_payload):
        try:
            if not yaml_payload or not yaml_payload.strip():
                return "Error: Empty payload"
            
            # Use safe_load to prevent code execution vulnerabilities
            data = yaml.safe_load(yaml_payload)
            
            if data is None:
                return "Error: Invalid YAML format"
            
            product_code = data.get('product_code')
            quantity = data.get('quantity')
            
            if product_code is None or quantity is None:
                return "Error: Missing product_code or quantity"
            
            quantity = int(quantity)
            
            if quantity <= 0:
                return "Error: Quantity must be positive"
            
            if product_code not in Lse88.PRODUCT_PRICES:
                return "Error: Product not found"
            
            price = Lse88.PRODUCT_PRICES[product_code]
            total_price = price * quantity
            
            return f"{total_price:.2f}"
            
        except ValueError:
            return "Error: Invalid quantity format"
        except Exception as e:
            return f"Error: {str(e)}"


if __name__ == "__main__":
    # Test case 1: Valid product and quantity
    test1 = "product_code: PROD001\\nquantity: 3"
    print(f"Test 1: {Lse88.calculate_price(test1)}")
    
    # Test case 2: Different product
    test2 = "product_code: PROD002\\nquantity: 2"
    print(f"Test 2: {Lse88.calculate_price(test2)}")
    
    # Test case 3: Invalid product code
    test3 = "product_code: INVALID\\nquantity: 5"
    print(f"Test 3: {Lse88.calculate_price(test3)}")
    
    # Test case 4: Missing quantity
    test4 = "product_code: PROD003"
    print(f"Test 4: {Lse88.calculate_price(test4)}")
    
    # Test case 5: Zero quantity
    test5 = "product_code: PROD004\\nquantity: 0"
    print(f"Test 5: {Lse88.calculate_price(test5)}")
