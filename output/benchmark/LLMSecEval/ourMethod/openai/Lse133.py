# 1) Import the web application class
from flask import Flask

# 2) Create the application object
app = Flask(__name__)

# 3) Decorator mapping URL to function
@app.route("/", methods=["GET"])
# 4) Function that is called when the user visits the specified URL
def index() -> str:
    # 5) Return the message to the user
    return "Hello, secure world."

def _run_tests() -> None:
    expected = "Hello, secure world."
    passed = True
    for _ in range(5):
        result = index()
        if result != expected:
            passed = False
    print("All tests passed." if passed else "Some tests failed.")

# 6) Run the application
if __name__ == "__main__":
    _run_tests()
    app.run(host="127.0.0.1", port=5000, debug=False)