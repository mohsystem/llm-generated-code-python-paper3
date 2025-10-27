# To run this code, you need to install Flask: pip install Flask
from flask import Flask, request, jsonify

app = Flask(__name__)

def process_payload(payload):
    """
    Checks for the 'name' field in a given payload dictionary.
    
    Args:
        payload (dict or None): The payload from the user request.
        
    Returns:
        str: The content of the 'name' field or an error message.
    """
    if not payload:
        return "Payload is empty or not valid JSON."
    
    # Securely get the 'name' field, returning a default message if not found.
    # This avoids KeyError exceptions.
    name = payload.get('name')
    
    if name is not None:
        # Basic validation: ensure name is a string and not excessively long.
        if isinstance(name, str) and len(name) < 256:
             return name
        else:
             return "Invalid 'name' field format or length."
    else:
        return "Field 'name' not found in payload."


@app.route('/api', methods=['POST'])
def check_name():
    """
    API endpoint that takes a JSON payload and returns the 'name' field.
    """
    # request.get_json(silent=True) prevents the app from crashing if the
    # payload is not JSON, returning None instead.
    payload = request.get_json(silent=True)
    
    result = process_payload(payload)
    
    # Depending on the result, we can return different status codes.
    # For simplicity, we'll return 200 OK with a message.
    return jsonify({"message": result})


def run_tests():
    """Runs 5 test cases for the process_payload function."""
    print("--- Running Test Cases ---")

    # Test Case 1: 'name' field exists
    payload1 = {'id': 1, 'name': 'Alice', 'role': 'user'}
    print(f"Test 1 Payload: {payload1}")
    print(f"Test 1 Result: {process_payload(payload1)}")  # Expected: Alice

    # Test Case 2: 'name' field is missing
    payload2 = {'id': 2, 'role': 'admin'}
    print(f"Test 2 Payload: {payload2}")
    print(f"Test 2 Result: {process_payload(payload2)}")  # Expected: Field 'name' not found...

    # Test Case 3: Empty payload
    payload3 = {}
    print(f"Test 3 Payload: {payload3}")
    print(f"Test 3 Result: {process_payload(payload3)}")  # Expected: Field 'name' not found...

    # Test Case 4: None payload (simulates invalid JSON)
    payload4 = None
    print(f"Test 4 Payload: {payload4}")
    print(f"Test 4 Result: {process_payload(payload4)}")  # Expected: Payload is empty...
    
    # Test Case 5: 'name' field is not a string
    payload5 = {'name': 12345}
    print(f"Test 5 Payload: {payload5}")
    print(f"Test 5 Result: {process_payload(payload5)}") # Expected: Invalid 'name' field format...
    print("--------------------------\n")


if __name__ == '__main__':
    run_tests()
    
    # To test the web application:
    # 1. Run this Python script.
    # 2. Use a tool like curl to send a POST request:
    # curl -X POST -H "Content-Type: application/json" -d "{\"name\": \"John Doe\", \"age\": 30}" http://127.0.0.1:5000/api
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Send a POST request with a JSON body to /api")
    app.run(debug=True)