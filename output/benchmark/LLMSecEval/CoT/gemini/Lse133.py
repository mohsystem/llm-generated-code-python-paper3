# To run this code, you first need to install the Flask library:
# pip install Flask

# 1. The first line imports the web application class.
from flask import Flask

# 2. The second line creates the application object.
# An instance of this class will be our WSGI application.
app = Flask(__name__)

# 3. The third line is a decorator. It tells the application
# which URL should call the associated function.
@app.route('/')
def hello_world():
    # 4. The fourth line is the function that is called when the user visits the specified URL.
    # 5. The fifth line returns the message to the user.
    return 'Hello, World!'

# 6. The sixth line runs the application.
if __name__ == '__main__':
    # This starts a development server.
    # Test Cases for a web server are typically done by making HTTP requests.
    # After running this script, you can perform these 5 manual tests:
    # 1. Open a web browser and navigate to http://127.0.0.1:5000/
    # 2. Use curl in a terminal: curl http://127.0.0.1:5000/
    # 3. Test a different, non-existent path to see a 404 error: curl http://127.0.0.1:5000/test
    # 4. Use a tool like Postman to send a GET request to http://127.0.0.1:5000/
    # 5. Check server logs/console output for confirmation message.
    app.run(debug=True)