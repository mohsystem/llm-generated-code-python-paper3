
# Python using Flask framework
from flask import Flask, render_template_string

app = Flask(__name__)

# HTML template embedded (alternatively, create hello.html in templates folder)
HELLO_TEMPLATE = """\n<!DOCTYPE html>\n<html>\n<head><title>Hello</title></head>\n<body>\n    <h1>Hello, {{ username }}!</h1>\n</body>\n</html>\n"""

@app.route('/hello/<username>')
def hello(username):
    return render_template_string(HELLO_TEMPLATE, username=username)

if __name__ == '__main__':
    # Test cases demonstration
    print("Server starting. Test the following URLs:")
    print("http://localhost:5000/hello/John")
    print("http://localhost:5000/hello/Alice")
    print("http://localhost:5000/hello/Bob")
    print("http://localhost:5000/hello/Charlie")
    print("http://localhost:5000/hello/Diana")
    
    app.run(debug=True)

# Alternatively, if using external hello.html file in templates folder:
# from flask import render_template
# @app.route('/hello/<username>')
# def hello(username):
#     return render_template('hello.html', username=username)
