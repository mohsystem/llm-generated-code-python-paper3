import json
from flask import Flask, request, jsonify

app = Flask(__name__)

PRODUCT_PRICES = {
    "PROD001": 19.99,
    "PROD002": 25.50,
    "PROD003": 5.75,
    "PROD004": 99.99,
}

def get_product_price(product_code: str) -> float | None:
    """Returns the price for a given product code."""
    return PRODUCT_PRICES.get(product_code)

@app.route('/price', methods=['GET'])
def calculate_price():
    """Calculates the total price for a product and quantity."""
    product_code = request.args.get('code')
    quantity_str = request.args.get('quantity')

    if not product_code or not quantity_str:
        return jsonify({"error": "Missing 'code' or 'quantity' parameter"}), 400

    price = get_product_price(product_code)
    if price is None:
        return jsonify({"error": "Product code not found"}), 404

    try:
        quantity = int(quantity_str)
        if not (0 < quantity <= 10000):
            return jsonify({"error": "Invalid quantity. Must be between 1 and 10000."}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Quantity must be a valid integer"}), 400

    total_price = price * quantity

    response = {
        "product_code": product_code,
        "quantity": quantity,
        "unit_price": price,
        "total_price": round(total_price, 2)
    }
    return jsonify(response)

if __name__ == '__main__':
    # --- Test Cases ---
    # In a separate terminal, run the following curl commands once the server is running.
    # 1. Valid product and quantity: curl "http://127.0.0.1:5000/price?code=PROD001&quantity=10"
    # 2. Another valid product: curl "http://127.0.0.1:5000/price?code=PROD004&quantity=2"
    # 3. Invalid product code: curl "http://127.0.0.1:5000/price?code=INVALID&quantity=5"
    # 4. Invalid quantity (negative): curl "http://127.0.0.1:5000/price?code=PROD002&quantity=-1"
    # 5. Missing code parameter: curl "http://127.0.0.1:5000/price?quantity=3"
    # --------------------
    app.run(host='0.0.0.0', port=5000)