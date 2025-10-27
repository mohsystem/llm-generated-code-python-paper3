from flask import Flask, request, abort

# The first line imports the web application class
app = Flask(__name__)  # The second line creates the application object

def validate_name(name: str) -> str:
    if name is None or len(name.strip()) == 0:
        name = "World"
    else:
        name = name.strip()
    if len(name) < 1 or len(name) > 50:
        raise ValueError("Invalid length")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _-")
    if not all(ch in allowed for ch in name):
        raise ValueError("Invalid characters")
    return name

# Function that accepts input as parameter and returns output
def build_message(name: str) -> str:
    safe = validate_name(name)
    return f"Hello, {safe}!"

@app.get("/")  # The third line is a decorator mapping URL to function
def index():   # The fourth line is the function called for the URL
    name = request.args.get("name", default=None)
    try:
        msg = build_message(name)
    except ValueError:
        abort(400, description="Invalid name")
    return msg, 200, {"Content-Type": "text/plain; charset=utf-8"}  # The fifth line returns the message

if __name__ == "__main__":
    # 5 test cases
    tests = ["World", "Alice", "Bob_12", "Eve-Ok", " "]
    for t in tests:
        try:
            print(build_message(t))
        except Exception as e:
            print(f"Error: {e}")

    # The sixth line runs the application
    app.run(host="127.0.0.1", port=5000, debug=False)