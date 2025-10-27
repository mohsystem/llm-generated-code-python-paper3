from flask import Flask, request, jsonify

# Using a dictionary to store product prices
product_prices = {
    "P100": 10.50,
    "P200": 25.00,
    "P300": 5.75,
    "P400": 19.99,
}

app = Flask(__name__)

def get_product_price(product_code):
    """
    Returns the price for a given product code.
    Args:
        product_code: The code of the product.
    Returns:
        The price of the product or None if not found.
    """
    return product_prices.get(product_code)

@app.route('/calculate_price', methods=['GET'])
def calculate_price():
    """
    Calculates the total price for a given product and quantity.
    Expects 'code' and 'quantity' as query parameters.
    """
    product_code = request.args.get('code')
    quantity_str = request.args.get('quantity')

    if not product_code or not quantity_str:
        return jsonify({"error": "'code' and 'quantity' parameters are required."}), 400

    price = get_product_price(product_code)
    if price is None:
        return jsonify({"error": f"Product code '{product_code}' not found."}), 404

    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({"error": "Quantity must be a positive integer."}), 400

    total_price = price * quantity
    
    response = {
        "product_code": product_code,
        "quantity": quantity,
        "unit_price": price,
        "total_price": round(total_price, 2)
    }
    return jsonify(response), 200

def run_tests():
    """Runs 5 test cases for the business logic."""
    print("--- Running Test Cases ---")
    
    # Test Case 1: Valid product
    price = get_product_price("P100")
    print(f"Test 1: P100 Price: ${price:.2f}" if price is not None else "Test 1: P100 not found")
    
    # Test Case 2: Another valid product
    price = get_product_price("P300")
    print(f"Test 2: P300 Price: ${price:.2f}" if price is not None else "Test 2: P300 not found")

    # Test Case 3: Invalid product
    price = get_product_price("P999")
    print(f"Test 3: P999 Price: {'Not found as expected' if price is None else 'Error: Found unexpected price'}")

    # Test Case 4: Empty string product code
    price = get_product_price("")
    print(f"Test 4: '' Price: {'Not found as expected' if price is None else 'Error: Found unexpected price'}")
    
    # Test Case 5: None as product code
    price = get_product_price(None)
    print(f"Test 5: None Price: {'Not found as expected' if price is None else 'Error: Found unexpected price'}")
    
    print("--------------------------\n")


if __name__ == '__main__':
    run_tests()
    print("Starting Flask server on port 5000")
    print("Try accessing: http://127.0.0.1:5000/calculate_price?code=P200&quantity=3")
    app.run(host='0.0.0.0', port=5000)