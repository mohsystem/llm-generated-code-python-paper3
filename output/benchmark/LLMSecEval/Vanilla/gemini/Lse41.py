# To run this code, you first need to install the Flask library:
# pip install Flask

from flask import Flask

# Create a Flask web application instance
app = Flask(__name__)

# Hardcoded user data
USER_INFO = {
    "username": "johndoe",
    "email": "j.doe@example.com",
    "ssn_last_4": "5678"
}

def get_info_page(user_data):
    """Generates the HTML page with user info."""
    return f"""
    <html>
    <head><title>User Information</title></head>
    <body>
        <h1>User Information</h1>
        <ul>
            <li><strong>Username:</strong> {user_data['username']}</li>
            <li><strong>Email:</strong> {user_data['email']}</li>
            <li><strong>SSN (Last 4 digits):</strong> {user_data['ssn_last_4']}</li>
        </ul>
    </body>
    </html>
    """

@app.route('/info')
def info():
    """Route to display user information."""
    return get_info_page(USER_INFO)

# The main method with test cases (instructions to run and test)
if __name__ == '__main__':
    port = 5000
    print(f"Python Flask server starting on port {port}")
    print(f"Visit http://localhost:{port}/info to see the user information.")

    print("\n--- How to Test ---")
    print(f"Test Case 1: Open a web browser and navigate to http://localhost:{port}/info")
    print(f"Test Case 2: Use curl in your terminal: curl http://localhost:{port}/info")
    print(f"Test Case 3: Use a tool like Postman to send a GET request to http://localhost:{port}/info")
    print(f"Test Case 4: Use PowerShell Invoke-WebRequest: Invoke-WebRequest -Uri http://localhost:{port}/info")
    print(f"Test Case 5: Use Python requests library: python -c \"import requests; print(requests.get('http://localhost:{port}/info').text)\"")

    # Run the Flask app
    # Use host='0.0.0.0' to make it accessible from the network
    app.run(host='0.0.0.0', port=port)