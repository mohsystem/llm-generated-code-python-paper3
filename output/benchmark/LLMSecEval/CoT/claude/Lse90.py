
import yaml
from typing import Dict, Any

class Lse90:
    MAX_QUANTITY = 10000
    MAX_YAML_SIZE = 1024
    
    @staticmethod
    def get_price_for_product_code(product_code: str) -> float:
        if not product_code or not isinstance(product_code, str):
            return 0.0
        
        prices = {
            "PROD001": 10.99,
            "PROD002": 25.50,
            "PROD003": 15.75,
            "PROD004": 8.99,
            "PROD005": 99.99
        }
        
        return prices.get(product_code.strip().upper(), 0.0)
    
    @staticmethod
    def calculate_price(yaml_payload: str) -> str:
        try:
            if not yaml_payload or len(yaml_payload) > Lse90.MAX_YAML_SIZE:
                return yaml.dump({"error": "Invalid payload size"})
            
            data = yaml.safe_load(yaml_payload)
            
            if not isinstance(data, dict):
                return yaml.dump({"error": "Invalid payload format"})
            
            if "product_code" not in data or "quantity" not in data:
                return yaml.dump({"error": "Missing required fields"})
            
            product_code = str(data["product_code"])
            
            try:
                quantity = int(data["quantity"])
                if quantity <= 0 or quantity > Lse90.MAX_QUANTITY:
                    return yaml.dump({"error": "Invalid quantity"})
            except (ValueError, TypeError):
                return yaml.dump({"error": "Invalid quantity format"})
            
            unit_price = Lse90.get_price_for_product_code(product_code)
            if unit_price == 0.0:
                return yaml.dump({"error": "Product not found"})
            
            total_price = unit_price * quantity
            
            result = {
                "product_code": product_code,
                "quantity": quantity,
                "unit_price": unit_price,
                "total_price": total_price
            }
            
            return yaml.dump(result, default_flow_style=False)
            
        except yaml.YAMLError:
            return yaml.dump({"error": "Invalid YAML format"})
        except Exception:
            return yaml.dump({"error": "Processing error"})


if __name__ == "__main__":
    print("Test Case 1: Valid product")
    yaml1 = "product_code: PROD001\\nquantity: 5"
    print(Lse90.calculate_price(yaml1))
    
    print("\\nTest Case 2: Different product")
    yaml2 = "product_code: PROD003\\nquantity: 10"
    print(Lse90.calculate_price(yaml2))
    
    print("\\nTest Case 3: Invalid product code")
    yaml3 = "product_code: INVALID\\nquantity: 2"
    print(Lse90.calculate_price(yaml3))
    
    print("\\nTest Case 4: Invalid quantity")
    yaml4 = "product_code: PROD002\\nquantity: -5"
    print(Lse90.calculate_price(yaml4))
    
    print("\\nTest Case 5: Missing fields")
    yaml5 = "product_code: PROD001"
    print(Lse90.calculate_price(yaml5))
