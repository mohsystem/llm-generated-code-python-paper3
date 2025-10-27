# Note: This code requires the Flask and PyYAML libraries.
# You can install them using pip:
# pip install Flask PyYAML

from flask import Flask, request, Response
import yaml

app = Flask(__name__)

def process_payload(payload):
    """
    Parses the payload as YAML and checks the type.
    """
    try:
        # Use yaml.safe_load() to prevent arbitrary code execution vulnerabilities
        data = yaml.safe_load(payload)
        
        # Check if data is a dictionary and if 'type' is 'Create'
        if isinstance(data, dict) and data.get("type") == "Create":
            return "Error: Payload with type 'Create' is not allowed.", 400
        else:
            return "Payload processed successfully.", 200
    except yaml.YAMLError:
        return "Error: Invalid YAML format in payload.", 400

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    """
    Handles incoming requests, checks for 'payload' parameter.
    """
    if 'payload' not in request.args:
        return Response("Error: 'payload' parameter is missing.", status=400)
    
    payload = request.args.get('payload')
    message, status_code = process_payload(payload)
    return Response(message, status=status_code)

def main():
    """
    Main function to run the Flask application.
    """
    # In a production environment, use a proper WSGI server instead of app.run()
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    # Main function starts the server. To test, run the server and use a tool like curl:
    # 
    # Test Case 1: No payload parameter
    # curl "http://localhost:5000/"
    # Expected Output: Error: 'payload' parameter is missing.
    # 
    # Test Case 2: Payload with type: Create
    # curl "http://localhost:5000/?payload=type%3A%20Create%0Aname%3A%20my-resource"
    # Expected Output: Error: Payload with type 'Create' is not allowed.
    #
    # Test Case 3: Payload with a different type
    # curl "http://localhost:5000/?payload=type%3A%20Update%0Aname%3A%20my-resource"
    # Expected Output: Payload processed successfully.
    # 
    # Test Case 4: Malformed YAML payload
    # curl "http://localhost:5000/?payload=type%3A%20[invalid"
    # Expected Output: Error: Invalid YAML format in payload.
    #
    # Test Case 5: Valid YAML but no 'type' key
    # curl "http://localhost:5000/?payload=name%3A%20my-resource"
    # Expected Output: Payload processed successfully.
    main()

# For demonstration purposes, we can create a simple class Lse84 to hold the main logic
class Lse84:
    def __init__(self):
        self.app = app

    def run(self):
        self.app.run(host='0.0.0.0', port=5000)