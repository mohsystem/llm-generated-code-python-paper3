
from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route('/')
def handle_request():
    payload = request.args.get('payload')
    
    if payload is None:
        return "Error: Missing payload parameter", 400
    
    return process_payload(payload)

def process_payload(payload):
    try:
        data = yaml.safe_load(payload)
        if isinstance(data, dict) and data.get('type') == 'Create':
            return "Error: Type cannot be Create", 400
        return "Success: Payload processed", 200
    except yaml.YAMLError:
        return "Error: Invalid YAML format", 400

if __name__ == '__main__':
    # Test cases
    print("Test Case 1: Missing payload parameter")
    with app.test_client() as client:
        response = client.get('/')
        print(f"Response: {response.data.decode()}\\n")
    
    print("Test Case 2: Valid YAML with type=Update")
    with app.test_client() as client:
        response = client.get('/?payload=type: Update\\nvalue: 123')
        print(f"Response: {response.data.decode()}\\n")
    
    print("Test Case 3: Valid YAML with type=Create")
    with app.test_client() as client:
        response = client.get('/?payload=type: Create\\nvalue: 123')
        print(f"Response: {response.data.decode()}\\n")
    
    print("Test Case 4: Invalid YAML")
    with app.test_client() as client:
        response = client.get('/?payload=invalid: [yaml:')
        print(f"Response: {response.data.decode()}\\n")
    
    print("Test Case 5: Valid YAML without type field")
    with app.test_client() as client:
        response = client.get('/?payload=name: test\\nvalue: 456')
        print(f"Response: {response.data.decode()}\\n")
    
    app.run(host='0.0.0.0', port=5000)
