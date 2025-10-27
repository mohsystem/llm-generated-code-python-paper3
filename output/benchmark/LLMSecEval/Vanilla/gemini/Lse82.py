# Before running, you need to install Flask:
# pip install Flask
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api', methods=['GET'])
def get_name_from_payload():
    """
    Gets the payload parameter from the URL, loads it as a dictionary (JSON),
    and returns the value associated with the 'name' key.
    """
    payload_str = request.args.get('payload')

    if not payload_str:
        return jsonify({"error": "Payload parameter is missing."}), 400

    try:
        # Load the payload string into a dictionary
        data = json.loads(payload_str)
        if not isinstance(data, dict):
             raise TypeError("Payload must be a JSON object.")
    except (json.JSONDecodeError, TypeError) as e:
        return jsonify({"error": f"Invalid payload format: {e}"}), 400

    # Get the 'name' value from the dictionary
    name = data.get('name')

    if name is None:
        return jsonify({"error": "'name' key not found in payload."}), 400

    return jsonify({"name": name})

def main():
    """Main function to run the web app and provide test cases."""
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Use Ctrl+C to stop the server.")
    print("\n--- Test Cases ---")
    print("Run the following commands in your terminal:")
    print("1) Test Case 1 (Standard):")
    print("   curl 'http://127.0.0.1:5000/api?payload=%7B%22name%22%3A%22JohnDoe%22%2C%22age%22%3A30%7D'")
    print("   Expected output: {\"name\":\"JohnDoe\"}\n")
    print("2) Test Case 2 (Different Name):")
    print("   curl 'http://127.0.0.1:5000/api?payload=%7B%22name%22%3A%22JaneSmith%22%7D'")
    print("   Expected output: {\"name\":\"JaneSmith\"}\n")
    print("3) Test Case 3 (No payload parameter):")
    print("   curl 'http://127.0.0.1:5000/api'")
    print("   Expected output: {\"error\":\"Payload parameter is missing.\"}\n")
    print("4) Test Case 4 (Payload without name key):")
    print("   curl 'http://127.0.0.1:5000/api?payload=%7B%22city%22%3A%22NewYork%22%7D'")
    print("   Expected output: {\"error\":\"'name' key not found in payload.\"}\n")
    print("5) Test Case 5 (Malformed payload):")
    print("   curl 'http://127.0.0.1:5000/api?payload=thisisnotjson'")
    print("   Expected output: {\"error\":\"Invalid payload format: ...\"}\n")
    
    # Setting use_reloader=False to prevent the main function from running twice
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

# This is the standard entry point for a Python script.
# The class name 'Lse82' is not applicable in this procedural style.
if __name__ == '__main__':
    main()