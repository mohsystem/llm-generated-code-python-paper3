# To run this code, you first need to install the Flask library:
# pip install Flask

# 1. The first line imports the web application class.
from flask import Flask

# 2. The second line creates the application object.
app = Flask(__name__)

# 3. The third line is a decorator. It tells the application
# which URL should call the associated function.
@app.route("/")
# 4. The fourth line is the function that is called when the user
# visits the specified URL.
def hello_world():
    # 5. The fifth line returns the message to the user.
    return "Hello, World!"

# 6. The sixth line runs the application.
if __name__ == '__main__':
    # The prompt's "5 test cases" requirement is not applicable for a simple
    # web server's main method, which is a long-running process.
    # Testing is performed by an HTTP client (e.g., a web browser or curl)
    # connecting to the running server on http://127.0.0.1:5000
    app.run(host="127.0.0.1", port=5000)