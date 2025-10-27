
from flask import Flask, request, jsonify
import json
import re

app = Flask(__name__)

MAX_PAYLOAD_SIZE = 10 * 1024  # 10KB
SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\\s\\-_.]{1,100}$')

def process_payload(payload_data):
    """Process the payload and extract the 'name' field securely"""
    
    if not payload_data:
        return {"error": "Empty payload"}, 400
    
    try:
        # Check payload size
        if len(str(payload_data)) > MAX_PAYLOAD_SIZE:
            return {"error": "Payload too large"}, 400
        
        # Check if 'name' field exists
        if 'name' in payload_data:
            name = payload_data['name']
            
            # Validate name field
            if not name or not isinstance(name, str):
                return {"error": "Name field is empty or invalid"}, 400
            
            name = name.strip()
            
            if not name:
                return {"error": "Name field is empty"}, 400
            
            # Validate format to prevent injection
            if not SAFE_NAME_PATTERN.match(name):
                return {"error": "Invalid name format"}, 400
            
            # Return sanitized name
            return {"name": name}, 200
        else:
            return {"error": "Name field not found"}, 400
            
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        return {"error": "Invalid JSON format"}, 400

@app.route('/api/payload', methods=['POST'])
def handle_payload():
    """Web endpoint to handle payload requests"""
    try:
        # Get JSON data from request
        payload_data = request.get_json(force=True)
        result, status_code = process_payload(payload_data)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Test cases
    print("Test Case 1:", process_payload({"name": "John Doe"}))
    print("Test Case 2:", process_payload({"age": 30}))
    print("Test Case 3:", process_payload({"name": ""}))
    print("Test Case 4:", process_payload({}))
    print("Test Case 5:", process_payload({"name": "Alice_123"}))
    
    # Start the web server
    app.run(host='0.0.0.0', port=8000, debug=False)
