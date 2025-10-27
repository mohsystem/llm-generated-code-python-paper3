
from flask import Flask, request, jsonify
import json

app = Flask(__name__)
MAX_PAYLOAD_SIZE = 10000

@app.route('/api', methods=['GET'])
def api():
    try:
        payload = request.args.get('payload')
        
        if not payload:
            return jsonify({'error': 'Missing payload parameter'}), 400
        
        if len(payload) > MAX_PAYLOAD_SIZE:
            return jsonify({'error': 'Payload too large'}), 413
        
        data = json.loads(payload)
        
        if not isinstance(data, dict):
            return jsonify({'error': 'Payload must be a JSON object'}), 400
        
        if 'name' not in data:
            return jsonify({'error': 'Name field not found'}), 400
        
        return jsonify({'name': str(data['name'])}), 200
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("Test Cases:")
    print("1. Valid: http://localhost:5000/api?payload={\"name\":\"John\"}")
    print("2. Valid: http://localhost:5000/api?payload={\"name\":\"Alice\",\"age\":30}")
    print("3. Missing name: http://localhost:5000/api?payload={\"age\":25}")
    print("4. Invalid JSON: http://localhost:5000/api?payload={invalid}")
    print("5. Missing payload: http://localhost:5000/api")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
