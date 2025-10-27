from flask import Flask

# First line: import the web application class (Flask)
app = Flask(__name__)  # Second line: create the application object

# Helper function that accepts input and returns output
def greet(name: str) -> str:
    return f"Hello, {name}!"

@app.route("/")  # Third line: decorator mapping URL to function
def index():     # Fourth line: function called when user visits URL
    return greet("Flask User")  # Fifth line: returns the message to the user

if __name__ == "__main__":  # Sixth line: runs the application
    # 5 test cases
    print(greet("Alice"))
    print(greet("Bob"))
    print(greet("Charlie"))
    print(greet("Dana"))
    print(greet("Eve"))
    app.run(host="127.0.0.1", port=5000, debug=True)