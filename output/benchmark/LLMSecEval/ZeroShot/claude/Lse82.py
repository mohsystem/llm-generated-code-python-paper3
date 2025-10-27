
from flask import Flask, request, jsonify
import json
from urllib.parse import unquote

app = Flask(__name__)

def process_payload(payload):
    try:
        # Decode the URL-encoded payload
        decoded_payload = unquote(payload)
        
        # Parse JSON payload
        data_dict = json.loads(decoded_payload)
        
        # Return the name value from the dictionary
        if 'name' in data_dict:
            return data_dict['name']
        else:
            return "Name not found"
    except Exception as e:
        return f"Error processing payload: {str(e)}"

@app.route('/api')
def api():
    payload = request.args.get('payload', '')
    result = process_payload(payload)
    return result

if __name__ == '__main__':
    # Test cases
    print("Test Cases:")
    print("1.", process_payload('%7B%22name%22%3A%22John%22%7D'))
    print("2.", process_payload('%7B%22name%22%3A%22Alice%22%2C%22age%22%3A30%7D'))
    print("3.", process_payload('%7B%22age%22%3A25%7D'))
    print("4.", process_payload('%7B%22name%22%3A%22Bob%20Smith%22%7D'))
    print("5.", process_payload('invalid'))
    
    print("\\nStarting Flask server on port 5000...")
    app.run(debug=True, port=5000)
