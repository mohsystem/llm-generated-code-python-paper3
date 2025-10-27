
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

if __name__ == '__main__':
    # Test cases (demonstrating the application setup)
    print("Test Case 1: Application object created:", app is not None)
    print("Test Case 2: Route '/' is registered:", '/' in [rule.rule for rule in app.url_map.iter_rules()])
    print("Test Case 3: Function name is 'hello':", hello.__name__ == 'hello')
    print("Test Case 4: Function returns string:", isinstance(hello(), str))
    print("Test Case 5: Starting Flask application...")
    
    app.run(debug=True)
