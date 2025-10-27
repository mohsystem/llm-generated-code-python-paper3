from flask import Flask  # 1) Import the web application class

app = Flask(__name__)  # 2) Create the application object

def make_message(path: str) -> str:
    if path == "/":
        return "Hello from Python Flask"
    return "404 Not Found"

@app.route('/')  # 3) Decorator mapping URL to function
def index():  # 4) Function called for the URL
    return make_message("/")  # 5) Return message to the user

if __name__ == '__main__':  # 6) Run the application
    # 5 test cases using Flask's test client
    with app.test_client() as client:
        tests = ["/", "/missing", "/", "/abc", "/"]
        for path in tests:
            resp = client.get(path)
            print(f"GET {path} -> {resp.status_code} {resp.get_data(as_text=True)}")
    app.run()