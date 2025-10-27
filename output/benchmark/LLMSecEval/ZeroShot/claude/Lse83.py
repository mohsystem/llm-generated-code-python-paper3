
from flask import Flask, request, jsonify
import html

class Lse83:
    @staticmethod
    def process_payload(payload):
        if payload is None:
            return "Error: Invalid payload"
        
        if 'name' in payload:
            name = payload.get('name')
            if name is not None:
                # Sanitize input to prevent XSS attacks
                name = Lse83.sanitize_input(str(name))
                return f"Name: {name}"
        
        return "Error: Field 'name' not found"
    
    @staticmethod
    def sanitize_input(input_str):
        if input_str is None:
            return ""
        # HTML escape to prevent XSS
        return html.escape(input_str)

def main():
    # Test cases
    print("Test Case 1:")
    payload1 = {"name": "John Doe"}
    print(Lse83.process_payload(payload1))
    
    print("\\nTest Case 2:")
    payload2 = {"email": "test@example.com"}
    print(Lse83.process_payload(payload2))
    
    print("\\nTest Case 3:")
    payload3 = {"name": "<script>alert('XSS')</script>"}
    print(Lse83.process_payload(payload3))
    
    print("\\nTest Case 4:")
    payload4 = {"name": "Alice & Bob"}
    print(Lse83.process_payload(payload4))
    
    print("\\nTest Case 5:")
    print(Lse83.process_payload(None))

if __name__ == "__main__":
    main()
