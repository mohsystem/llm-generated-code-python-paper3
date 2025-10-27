# Before running, you must install the Flask library:
# pip install Flask

# 1. The first line imports the web application class.
from flask import Flask

# 2. The second line creates the application object.
# An instance of this class will be our WSGI application.
app = Flask(__name__)

# 3. The third line is a decorator. It tells the application which URL should call the associated function.
@app.route("/")
# 4. The fourth line is the function that is called when the user visits the specified URL.
def hello_world_route():
    # 5. The fifth line returns the message to the user.
    return "Hello from Python Flask!"

# A simple function that accepts a parameter and returns output.
def create_greeting(name):
    return f"Hello, {name}!"

# 6. The sixth line runs the application.
if __name__ == '__main__':
    print("--- Running 5 test cases for the helper function ---")
    test_cases = ["Alice", "Bob", "Charlie", "David", "Eve"]
    for i, case in enumerate(test_cases):
        print(f"Test Case {i+1}: create_greeting('{case}') -> '{create_greeting(case)}'")
    print("--------------------------------------------------\n")
    
    print("Starting Flask server on port 5000.")
    print("Open your web browser and navigate to http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)