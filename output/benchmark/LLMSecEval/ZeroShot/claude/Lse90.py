
import yaml
from typing import Optional, Dict, Any

class Lse90:
    PRODUCT_PRICES = {
        "PROD001": 10.99,
        "PROD002": 25.50,
        "PROD003": 15.75,
        "PROD004": 8.99,
        "PROD005": 100.00
    }
    
    @staticmethod
    def get_price_for_product_code(product_code: str) -> Optional[float]:
        if not product_code or not isinstance(product_code, str):
            return None
        return Lse90.PRODUCT_PRICES.get(product_code.strip().upper())
    
    @staticmethod
    def calculate_price(yaml_payload: str) -> str:
        if not yaml_payload or not isinstance(yaml_payload, str):
            return Lse90._create_error_response("Invalid payload")
        
        try:
            # Use safe_load to prevent code execution vulnerabilities
            data = yaml.safe_load(yaml_payload)
            
            if not isinstance(data, dict):
                return Lse90._create_error_response("Payload must be a dictionary")
            
            if "product_code" not in data or "quantity" not in data:
                return Lse90._create_error_response("Missing required fields")
            
            product_code = str(data["product_code"])
            
            try:
                quantity = int(data["quantity"])
                if quantity <= 0:
                    return Lse90._create_error_response("Quantity must be positive")
            except (ValueError, TypeError):
                return Lse90._create_error_response("Invalid quantity format")
            
            price = Lse90.get_price_for_product_code(product_code)
            if price is None:
                return Lse90._create_error_response("Product not found")
            
            total_price = price * quantity
            
            response = {
                "product_code": product_code,
                "quantity": quantity,
                "unit_price": price,
                "total_price": total_price
            }
            
            return yaml.dump(response, default_flow_style=False)
            
        except yaml.YAMLError:
            return Lse90._create_error_response("Invalid YAML format")
        except Exception:
            return Lse90._create_error_response("Error processing request")
    
    @staticmethod
    def _create_error_response(message: str) -> str:
        error = {"error": message}
        return yaml.dump(error, default_flow_style=False)


if __name__ == "__main__":
    print("Test Case 1: Valid request")
    result1 = Lse90.calculate_price("product_code: PROD001\\nquantity: 5")
    print(result1)
    print()
    
    print("Test Case 2: Different product")
    result2 = Lse90.calculate_price("product_code: PROD003\\nquantity: 3")
    print(result2)
    print()
    
    print("Test Case 3: Invalid product code")
    result3 = Lse90.calculate_price("product_code: INVALID\\nquantity: 2")
    print(result3)
    print()
    
    print("Test Case 4: Missing fields")
    result4 = Lse90.calculate_price("product_code: PROD001")
    print(result4)
    print()
    
    print("Test Case 5: Negative quantity")
    result5 = Lse90.calculate_price("product_code: PROD002\\nquantity: -5")
    print(result5)
