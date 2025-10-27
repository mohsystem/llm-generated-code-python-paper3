
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    # Test cases
    with app.test_client() as client:
        print("Test Case 1:", client.get('/').data.decode())
        print("Test Case 2:", client.get('/').data.decode())
        print("Test Case 3:", client.get('/').data.decode())
        print("Test Case 4:", client.get('/').data.decode())
        print("Test Case 5:", client.get('/').data.decode())
    
    # Uncomment to run the application
    # app.run(debug=False, host='0.0.0.0', port=8000)
