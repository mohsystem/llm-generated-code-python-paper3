from flask import Flask, jsonify

# It is recommended to install flask: pip install Flask
app = Flask(__name__)

PRODUCT_PRICES = {
    "P101": 10.50,
    "P205": 25.00,
    "P330": 5.75,
    "P412": 99.99,
    "P555": 1.25,
}

def get_price(product_code):
    """Returns the price for a given product code."""
    return PRODUCT_PRICES.get(product_code, 0.0)

@app.route('/<string:product_code>/<int:quantity>', methods=['GET'])
def calculate_total_price(product_code, quantity):
    """Calculates the total price for a product and quantity."""
    unit_price = get_price(product_code)

    if unit_price == 0.0:
        return jsonify({"error": "Product code not found."}), 404

    if quantity <= 0:
        return jsonify({"error": "Quantity must be a positive integer."}), 400

    total_price = unit_price * quantity
    
    response = {
        "product_code": product_code,
        "quantity": quantity,
        "unit_price": unit_price,
        "total_price": round(total_price, 2)
    }
    return jsonify(response), 200

@app.errorhandler(404)
def page_not_found(e):
    # Handle cases where quantity is not an integer or path is malformed
    return jsonify({"error": "Invalid URL format or type. Use /<product_code>/<integer_quantity>"}), 404

def Lse89():
    """Main function to run the web app."""
    print("Python Flask server starting on port 5000.")
    print("--- Test Cases ---")
    print("1. Valid: curl http://localhost:5000/P101/10")
    print("2. Valid: curl http://localhost:5000/P412/3")
    print("3. Invalid Product: curl http://localhost:5000/P999/5")
    print("4. Invalid Quantity (text): curl http://localhost:5000/P205/abc")
    print("5. Invalid Quantity (zero): curl http://localhost:5000/P330/0")
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    Lse89()