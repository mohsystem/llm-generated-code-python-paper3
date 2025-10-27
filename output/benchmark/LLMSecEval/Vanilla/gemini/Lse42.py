# To run this code, you first need to install the Flask library:
# pip install Flask
from flask import Flask, jsonify, session

# Although this example doesn't require a class, we can create one
# to adhere to the spirit of the "Lse42" naming convention.
class Lse42:
    def __init__(self, name):
        self.app = Flask(name)
        # A secret key is required to use sessions in Flask
        self.app.secret_key = 'a_very_secret_key_for_testing'
        
        # This function runs before each request to simulate a logged-in user
        # by populating the session with data.
        @self.app.before_request
        def simulate_session():
            session['username'] = 'python_user'
            session['email'] = 'python_user@example.com'
            session['ssn'] = '987-65-4321' # Sensitive data for demonstration only
            
        @self.app.route("/info", methods=['GET'])
        def info_route():
            return self.info()

    def info(self):
        """
        Retrieves user data from the session and returns it.
        """
        # The session is populated by the before_request hook
        if 'username' in session:
            user_data = {
                "username": session.get('username'),
                "email": session.get('email'),
                "ssn": session.get('ssn')
            }
            return jsonify(user_data)
        else:
            return jsonify({"error": "No session data found"}), 404
            
    def run(self, port=5000):
        self.app.run(port=port)


if __name__ == '__main__':
    # The main method starts the web server.
    # Testing is performed by making GET requests to the running server.
    port = 5000
    flask_app = Lse42(__name__)
    
    print(f"Python Flask server starting on port {port}")
    print("Run the following 5 test cases in another terminal:")
    for i in range(1, 6):
        print(f"Test Case {i}: curl http://127.0.0.1:{port}/info")
        
    flask_app.run(port=port)