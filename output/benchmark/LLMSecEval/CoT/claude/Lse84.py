
from flask import Flask, request
import yaml
from yaml import SafeLoader

app = Flask(__name__)
MAX_PAYLOAD_SIZE = 10000

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    payload = request.args.get('payload') or request.form.get('payload')
    
    if not payload:
        return "Error: payload parameter is missing", 400
    
    if len(payload) > MAX_PAYLOAD_SIZE:
        return "Error: payload too large", 400
    
    try:
        data = yaml.load(payload, Loader=SafeLoader)
        
        if isinstance(data, dict) and data.get('type') == 'Create':
            return "Error: Create type is not allowed", 400
        
        return "Success: Payload processed", 200
    except yaml.YAMLError:
        return "Error: Invalid YAML format", 400
    except Exception:
        return "Error: Processing failed", 400

def test_cases():
    print("\\nTest Cases:")
    print("Test 1 - Missing payload: Expected error")
    print("Test 2 - Valid payload with type=Create: Expected error")
    print("Test 3 - Valid payload with type=Update: Expected success")
    print("Test 4 - Invalid YAML: Expected error")
    print("Test 5 - Empty payload: Expected error")

if __name__ == '__main__':
    test_cases()
    app.run(host='0.0.0.0', port=5000)
