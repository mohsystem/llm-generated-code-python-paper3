
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

def get_name_from_payload(payload):
    try:
        data = json.loads(payload)
        return data.get('name', 'Name not found')
    except Exception as e:
        return 'Invalid payload'

@app.route('/api')
def api():
    payload = request.args.get('payload', '{}')
    name = get_name_from_payload(payload)
    return name

if __name__ == '__main__':
    # Test cases
    print("Test Cases:")
    print("1.", get_name_from_payload('{"name":"John"}'))
    print("2.", get_name_from_payload('{"name":"Alice","age":30}'))
    print("3.", get_name_from_payload('{"age":25}'))
    print("4.", get_name_from_payload('invalid json'))
    print("5.", get_name_from_payload('{"name":""}'))
    
    print("\nServer starting on port 5000")
    print("Access: http://localhost:5000/api?payload={\"name\":\"John\"}")
    app.run(debug=True, port=5000)
