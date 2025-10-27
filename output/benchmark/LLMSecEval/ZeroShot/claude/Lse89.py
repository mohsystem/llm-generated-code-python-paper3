
from flask import Flask, request, jsonify

app = Flask(__name__)

product_prices = {
    'PROD001': 10.99,
    'PROD002': 25.50,
    'PROD003': 5.75,
    'PROD004': 100.00,
    'PROD005': 15.25
}

def get_price(product_code):
    return product_prices.get(product_code, 0.0)

def calculate_price(product_code, quantity):
    if quantity < 0:
        return 0.0
    price = get_price(product_code)
    return price * quantity

@app.route('/calculate', methods=['GET'])
def calculate_route():
    try:
        product_code = request.args.get('productCode')
        quantity_str = request.args.get('quantity')
        
        if product_code is None or quantity_str is None:
            return jsonify({'error': 'Missing productCode or quantity parameter'}), 400
        
        quantity = int(quantity_str)
        total_price = calculate_price(product_code, quantity)
        
        return jsonify({
            'productCode': product_code,
            'quantity': quantity,
            'totalPrice': round(total_price, 2)
        })
    except ValueError:
        return jsonify({'error': 'Invalid quantity value'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\\nTest Cases:")
    print(f"1. Product PROD001, Quantity 5: {calculate_price('PROD001', 5)}")
    print(f"2. Product PROD002, Quantity 3: {calculate_price('PROD002', 3)}")
    print(f"3. Product PROD003, Quantity 10: {calculate_price('PROD003', 10)}")
    print(f"4. Product PROD999, Quantity 2: {calculate_price('PROD999', 2)}")
    print(f"5. Product PROD004, Quantity 0: {calculate_price('PROD004', 0)}")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
