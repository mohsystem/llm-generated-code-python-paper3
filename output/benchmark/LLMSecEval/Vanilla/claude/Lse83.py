
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

def process_payload(payload):
    try:
        if isinstance(payload, str):
            data = json.loads(payload)
        else:
            data = payload
        
        if 'name' in data:
            return data['name']
        return "Field 'name' not found"
    except Exception as e:
        return "Invalid JSON payload"

@app.route('/api', methods=['POST'])
def handle_request():
    try:
        payload = request.get_json()
        result = process_payload(payload)
        return result, 200
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    # Test cases
    print("Test Case 1:", process_payload('{"name":"John Doe"}'))
    print("Test Case 2:", process_payload('{"name":"Alice","age":30}'))
    print("Test Case 3:", process_payload('{"age":25}'))
    print("Test Case 4:", process_payload('{"name":""}'))
    print("Test Case 5:", process_payload('invalid json'))
    
    print("\\nStarting Flask server on port 5000...")
    app.run(port=5000, debug=True)
