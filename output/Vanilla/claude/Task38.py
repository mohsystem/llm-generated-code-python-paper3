
from flask import Flask, request, render_template_string

app = Flask(__name__)

FORM_TEMPLATE = """\n<!DOCTYPE html>\n<html>\n<head>\n    <title>User Input Form</title>\n</head>\n<body>\n    <h2>Enter Your Information</h2>\n    <form method="post" action="/submit">\n        Name: <input type="text" name="name" required><br><br>\n        Email: <input type="email" name="email" required><br><br>\n        Message: <textarea name="message" rows="4" cols="50" required></textarea><br><br>\n        <input type="submit" value="Submit">\n    </form>\n</body>\n</html>\n"""

DISPLAY_TEMPLATE = """\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Display User Input</title>\n</head>\n<body>\n    <h2>Your Submitted Information</h2>\n    <p><strong>Name:</strong> {{ name }}</p>\n    <p><strong>Email:</strong> {{ email }}</p>\n    <p><strong>Message:</strong> {{ message }}</p>\n    <br><a href="/">Go Back</a>\n</body>\n</html>\n"""

@app.route('/')
def index():
    return render_template_string(FORM_TEMPLATE)

@app.route('/submit', methods=['POST'])
def submit():
    name = request.form.get('name', '')
    email = request.form.get('email', '')
    message = request.form.get('message', '')
    
    return render_template_string(DISPLAY_TEMPLATE, name=name, email=email, message=message)

def process_input(name, email, message):
    return f"Name: {name}\\nEmail: {email}\\nMessage: {message}"

if __name__ == '__main__':
    print("Starting Flask web application...")
    print("\\nTest cases (simulated):")
    
    test_cases = [
        ("John Doe", "john@example.com", "Hello World"),
        ("Jane Smith", "jane@test.com", "Test message"),
        ("Bob Johnson", "bob@demo.com", "This is a sample"),
        ("Alice Brown", "alice@mail.com", "Flask web app test"),
        ("Charlie Wilson", "charlie@site.com", "Final test case")
    ]
    
    for i, (name, email, message) in enumerate(test_cases, 1):
        print(f"\\nTest Case {i}:")
        print(process_input(name, email, message))
    
    print("\\nStarting web server on http://127.0.0.1:5000/")
    app.run(debug=True)
