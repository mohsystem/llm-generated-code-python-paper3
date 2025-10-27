# This code requires the Flask library.
# Install it using: pip install Flask
from flask import Flask, request, jsonify

# The main class name 'Lse89' is not applicable in the same way for Python,
# but we are creating a Flask app instance.
app = Flask(__name__)

# In-memory database for product prices
PRODUCT_PRICES = {
    "A123": 10.50,
    "B456": 25.00,
    "C789": 5.75,
    "D101": 99.99
}

def get_price(product_code):
    """
    Returns the price for a given product code.
    
    Args:
        product_code: The code of the product.
    
    Returns:
        The price as a float, or None if not found.
    """
    return PRODUCT_PRICES.get(product_code)

@app.route('/price', methods=['GET'])
def calculate_price():
    """
    Calculates the total price for a given product and quantity.
    Expects 'product_code' and 'quantity' as query parameters.
    """
    product_code = request.args.get('product_code')
    quantity_str = request.args.get('quantity')

    if not product_code or not quantity_str:
        return jsonify({"error": "Missing product_code or quantity parameter"}), 400

    price = get_price(product_code)
    if price is None:
        return jsonify({"error": "Product code not found"}), 404

    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            return jsonify({"error": "Quantity must be a positive integer"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Quantity must be a valid integer"}), 400

    total_price = price * quantity
    response = {
        "product_code": product_code,
        "quantity": quantity,
        "total_price": round(total_price, 2)
    }
    return jsonify(response), 200

if __name__ == '__main__':
    # Running the main application
    port = 5000
    print(f"Python Flask server starting on port {port}")
    print("--- Test Cases (use curl or a browser) ---")
    print(f"1. Valid: curl \"http://localhost:{port}/price?product_code=A123&quantity=5\"")
    print(f"2. Not Found: curl \"http://localhost:{port}/price?product_code=X999&quantity=2\"")
    print(f"3. Invalid Quantity (text): curl \"http://localhost:{port}/price?product_code=B456&quantity=abc\"")
    print(f"4. Invalid Quantity (negative): curl \"http://localhost:{port}/price?product_code=C789&quantity=-3\"")
    print(f"5. Missing Parameter: curl \"http://localhost:{port}/price?product_code=A123\"")
    # For a production environment, use a proper WSGI server instead of app.run()
    # Setting debug=False is crucial for security in production.
    app.run(port=port, debug=False)