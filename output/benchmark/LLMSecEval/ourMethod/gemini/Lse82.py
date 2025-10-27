# This Python code creates a simple web server using the Flask framework.
#
# How to run:
# 1. Make sure you have Python and pip installed.
# 2. Install Flask:
#    pip install Flask
# 3. Run the script:
#    python your_script_name.py
# 4. The server will start on http://localhost:8080.

from flask import Flask, request, Response
import json

app = Flask(__name__)

@app.route('/api', methods=['GET'])
def get_name_from_payload():
    """
    Handles GET requests to /api. Extracts a 'name' value from a JSON
    payload provided in the URL query parameters.
    """
    payload_str = request.args.get('payload')

    if not payload_str:
        return Response("'payload' parameter is missing", status=400, mimetype='text/plain')

    try:
        data = json.loads(payload_str)
        
        if not isinstance(data, dict):
             return Response("Payload must be a JSON object.", status=400, mimetype='text/plain')
        
        name = data.get('name')

        if not isinstance(name, str):
            return Response("'name' key is missing or not a string in JSON payload", status=400, mimetype='text/plain')

        return Response(name, status=200, mimetype='text/plain')

    except json.JSONDecodeError:
        return Response("Invalid JSON format in 'payload'", status=400, mimetype='text/plain')
    except Exception:
        return Response("An unexpected error occurred", status=500, mimetype='text/plain')


def main():
    """Main function to print test cases and run the Flask app."""
    port = 8080
    print(f"Server starting on http://localhost:{port}")
    print("Use curl to test the API endpoint:")
    
    # Test cases (to be executed from a separate terminal):
    # 1. Valid request:
    print(f"curl 'http://localhost:{port}/api?payload=%7B%22name%22%3A%22world%22%7D'")
    # 2. Missing 'payload' parameter:
    print(f"curl 'http://localhost:{port}/api'")
    # 3. Invalid JSON in 'payload':
    print(f"curl 'http://localhost:{port}/api?payload=invalid-json'")
    # 4. 'name' key missing in JSON:
    print(f"curl 'http://localhost:{port}/api?payload=%7B%22other_key%22%3A%22value%22%7D'")
    # 5. 'name' value is not a string:
    print(f"curl 'http://localhost:{port}/api?payload=%7B%22name%22%3A123%7D'")

    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    main()