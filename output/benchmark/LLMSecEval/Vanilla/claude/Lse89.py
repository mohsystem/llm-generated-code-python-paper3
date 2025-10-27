
from flask import Flask, request

app = Flask(__name__)

prices = {
    'A001': 10.50,
    'A002': 15.75,
    'A003': 20.00,
    'A004': 25.50,
    'A005': 30.25
}

def get_price(product_code):
    return prices.get(product_code, 0.0)

def calculate_total(product_code, quantity):
    return get_price(product_code) * quantity

@app.route('/calculate')
def calculate():
    product_code = request.args.get('code', '')
    quantity = int(request.args.get('quantity', 1))
    total = calculate_total(product_code, quantity)
    return f"Product: {product_code}, Quantity: {quantity}, Total: ${total:.2f}"

if __name__ == '__main__':
    # Test cases
    print("Test Case 1:", calculate_total('A001', 2))
    print("Test Case 2:", calculate_total('A002', 3))
    print("Test Case 3:", calculate_total('A003', 1))
    print("Test Case 4:", calculate_total('A004', 5))
    print("Test Case 5:", calculate_total('A005', 4))
    
    app.run(port=5000, debug=True)
