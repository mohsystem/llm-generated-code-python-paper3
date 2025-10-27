# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, request, jsonify, Response
import json

app = Flask(__name__)

def process_api_request(payload):
    """
    Processes the payload to extract the 'name' value.
    This function is separate to be testable.
    """
    if not payload:
        return "Payload parameter is missing", 400

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return "Invalid JSON format in payload", 400

    if not isinstance(data, dict):
        return "Payload must be a JSON object", 400

    name = data.get("name")

    if name is None or not isinstance(name, str):
        return "'name' key is missing or not a string", 400

    return name, 200

@app.route('/api', methods=['GET'])
def get_name_from_payload():
    payload = request.args.get('payload')
    message, status_code = process_api_request(payload)
    return Response(message, status=status_code, mimetype='text/plain')

def run_tests():
    print("--- Test Cases ---")
    
    test_cases = [
        {"name": "Success", "payload": '{"name": "Alice", "age": 30}', "expected_msg": "Alice", "expected_code": 200},
        {"name": "Missing Payload", "payload": None, "expected_msg": "Payload parameter is missing", "expected_code": 400},
        {"name": "Invalid JSON", "payload": '{name: "Bob"}', "expected_msg": "Invalid JSON format in payload", "expected_code": 400},
        {"name": "Missing Name Key", "payload": '{"age": 25}', "expected_msg": "'name' key is missing or not a string", "expected_code": 400},
        {"name": "Payload is not a dictionary", "payload": '["item1", "item2"]', "expected_msg": "Payload must be a JSON object", "expected_code": 400},
    ]

    for i, test in enumerate(test_cases):
        print(f"Test {i+1}: {test['name']}")
        msg, code = process_api_request(test['payload'])
        print(f"  Input: {test['payload']}")
        print(f"  Output: '{msg}', Status: {code}")
        assert msg == test['expected_msg']
        assert code == test['expected_code']
        print("  Result: PASSED")
        
    print("\n--- To test with a running server ---")
    print("Run the script and use curl in another terminal:")
    print("1. Success: curl 'http://127.0.0.1:5000/api?payload=%7B%22name%22%3A%22Alice%22%2C%22age%22%3A30%7D'")
    print("2. Missing Payload: curl 'http://127.0.0.1:5000/api'")
    print("3. Invalid JSON: curl 'http://127.0.0.1:5000/api?payload=invalid-json'")
    print("4. Missing Name Key: curl 'http://127.0.0.1:5000/api?payload=%7B%22age%22%3A30%7D'")
    print("5. Payload is not a dictionary: curl 'http://127.0.0.1:5000/api?payload=%5B%22test%22%5D'")


if __name__ == '__main__':
    run_tests()
    # To run the web server, uncomment the line below
    # app.run(debug=True)