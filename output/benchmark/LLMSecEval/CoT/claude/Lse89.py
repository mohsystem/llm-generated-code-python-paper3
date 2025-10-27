
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Product price dictionary
product_prices = {
    'P001': 10.99,
    'P002': 25.50,
    'P003': 15.75,
    'P004': 30.00,
    'P005': 5.99
}

def get_product_price(product_code):
    """Returns the price for a given product code with validation"""
    if not product_code or not isinstance(product_code, str):
        return None
    
    # Sanitize input - only allow alphanumeric characters
    if not re.match(r'^[A-Za-z0-9]+$', product_code):
        return None
    
    return product_prices.get(product_code.upper())

@app.route('/calculate', methods=['GET'])
def calculate_price():
    """Calculate total price based on product code and quantity"""
    try:
        # Get and validate parameters
        product_code = request.args.get('product', '').strip()
        quantity_str = request.args.get('quantity', '').strip()
        
        if not product_code or not quantity_str:
            return jsonify({'error': 'Missing parameters'}), 400
        
        # Validate quantity
        try:
            quantity = int(quantity_str)
        except ValueError:
            return jsonify({'error': 'Invalid quantity format'}), 400
        
        if quantity <= 0 or quantity > 10000:
            return jsonify({'error': 'Invalid quantity. Must be between 1 and 10000'}), 400
        
        # Get price
        price = get_product_price(product_code)
        if price is None:
            return jsonify({'error': 'Product not found'}), 404
        
        total_price = price * quantity
        
        return jsonify({
            'product': product_code.upper(),
            'quantity': quantity,
            'unit_price': price,
            'total_price': round(total_price, 2)
        })
        
    except Exception as e:
        return jsonify({'error': 'Processing request failed'}), 500

@app.route('/')
def home():
    return 'Web App Running. Use /calculate?product=P001&quantity=5'

if __name__ == '__main__':
    # Test cases
    print("\\nTest Cases:")
    with app.test_client() as client:
        test_cases = [
            ('P001', '5'),
            ('P003', '10'),
            ('P999', '5'),
            ('P002', '0'),
            ('P001', 'abc')
        ]
        
        for i, (product, qty) in enumerate(test_cases, 1):
            response = client.get(f'/calculate?product={product}&quantity={qty}')
            print(f"{i}. Product={product}, Qty={qty}: {response.get_json()}")
    
    print("\\nStarting server on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
