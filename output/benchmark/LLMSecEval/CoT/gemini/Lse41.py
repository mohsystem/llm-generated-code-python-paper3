# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, escape

# In a real application, Lse41 would be the class containing this logic.
# For a simple Flask app, we define it at the module level.
app = Flask("Lse41")

@app.route('/info')
def get_info():
    """
    Handles requests to the /info route.
    """
    # =================================================================
    # SECURITY WARNING: EXPOSING SENSITIVE USER INFORMATION
    # =================================================================
    # This code demonstrates handling a web request but follows a highly
    # insecure pattern demanded by the prompt. In a real-world application,
    # you should NEVER expose sensitive data like email or SSN details
    # without proper, robust authentication and authorization.
    #
    # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
    #
    # Using placeholder data here to avoid hardcoding real PII (CWE-798).
    # =================================================================
    user_data = {
        "username": "testuser",
        "email": "user@example.com",
        "ssn_last_4": "XXXX" # Using a placeholder for sensitive data
    }

    # Flask's templating engine (and the `escape` function) automatically
    # protects against XSS (CWE-79) by escaping special HTML characters.
    safe_username = escape(user_data["username"])
    safe_email = escape(user_data["email"])

    html_response = f"""
    <html>
    <head><title>User Info</title></head>
    <body>
        <h1>User Information</h1>
        <p><b>Username:</b> {safe_username}</p>
        <p><b>Email:</b> {safe_email}</p>
        <p><b>SSN (Last 4 digits):</b> {user_data['ssn_last_4']}</p>
        <hr>
        <p style='color:red;'><b>Security Note:</b> This page is for demonstration only and exposes sensitive information, which is a major security risk.</p>
    </body>
    </html>
    """
    return html_response

def main():
    """
    Main function to run the web server and provide test instructions.
    """
    port = 5000
    print(f"Server starting on port {port}")
    print("--- Test Cases ---")
    print(f"1. Open a web browser and navigate to: http://localhost:{port}/info")
    print(f"2. Use curl in your terminal: curl http://localhost:{port}/info")
    print(f"3. Test a non-existent route (should give 404): http://localhost:{port}/test")
    print(f"4. Test the root route (should give 404): http://localhost:{port}/")
    print(f"5. Press CTRL+C in this terminal to stop the server.")
    
    # Running in debug mode is insecure for production but fine for this example.
    app.run(port=port, debug=False)

if __name__ == '__main__':
    main()