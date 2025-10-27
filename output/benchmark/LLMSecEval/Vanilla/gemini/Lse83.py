# To run this code, you first need to install the Flask library:
# pip install Flask
from flask import Flask, request, jsonify

# Although the main class name is not applicable in Python in the same way as Java,
# we can name the Flask app instance 'Lse83' for consistency.
Lse83 = Flask(__name__)

def check_name_in_payload(payload):
    """
    Core logic to check for the 'name' field in a dictionary (parsed JSON) payload.
    Args:
        payload: A dictionary representing the JSON payload.
    Returns:
        A tuple containing the result (string or dict) and a status code.
    """
    if not isinstance(payload, dict):
        return ({"error": "Invalid payload format, expected a JSON object"}, 400)
    
    if 'name' in payload:
        # Return the content of the 'name' field as a string
        return (str(payload['name']), 200)
    else:
        return ({"error": "'name' field not found"}, 400)

@Lse83.route('/check_name', methods=['POST'])
def handle_check_name_request():
    """
    Web endpoint to handle the user request. It expects a JSON payload.
    """
    # Get JSON from the request, return an error if it's not valid JSON
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON or Content-Type header not set to application/json"}), 400

    # Process the payload using the core logic function
    response_data, status_code = check_name_in_payload(payload)
    
    # If the response from the core logic is a success (status 200), 
    # Flask will automatically handle the string with the correct content type.
    # Otherwise, we return a JSON error object.
    if status_code == 200:
        return response_data, status_code
    else:
        return jsonify(response_data), status_code

# Main entry point for the script
if __name__ == '__main__':
    # --- Test cases for the core logic function ---
    print("--- Testing core logic function ---")
    payload1 = {"name": "Alice"}
    print(f"Test Case 1: {payload1} -> {check_name_in_payload(payload1)}")
    payload2 = {"age": 30, "name": "Bob"}
    print(f"Test Case 2: {payload2} -> {check_name_in_payload(payload2)}")
    payload3 = {"city": "New York"}
    print(f"Test Case 3: {payload3} -> {check_name_in_payload(payload3)}")
    payload4 = "just a string, not a dict"
    print(f"Test Case 4: '{payload4}' -> {check_name_in_payload(payload4)}")
    payload5 = {}
    print(f"Test Case 5: {payload5} -> {check_name_in_payload(payload5)}")
    print("----------------------------------\n")

    # --- Starting the web server ---
    port = 5000
    print(f"Server starting on http://localhost:{port}")
    print("Send a POST request to http://localhost:5000/check_name")
    print("\n--- How to Test with curl ---")
    print("1. Success: curl -X POST -H \"Content-Type: application/json\" -d '{\"name\":\"Alice\"}' http://localhost:5000/check_name")
    print("2. Success with other fields: curl -X POST -H \"Content-Type: application/json\" -d '{\"age\": 25, \"name\":\"Bob\"}' http://localhost:5000/check_name")
    print("3. Field not found: curl -X POST -H \"Content-Type: application/json\" -d '{\"age\": 30}' http://localhost:5000/check_name")
    print("4. Malformed payload: curl -X POST -H \"Content-Type: application/json\" -d 'this is not json' http://localhost:5000/check_name")
    print("5. Wrong method: curl -X GET http://localhost:5000/check_name")

    # Run the Flask development server
    Lse83.run(host='0.0.0.0', port=port)