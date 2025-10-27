
from flask import Flask, escape
from markupsafe import escape as markup_escape

app = Flask(__name__)

@app.route('/hello/<username>')
def hello(username):
    return 'Hello ' + markup_escape(username)

# Alternative implementation without Flask for standalone execution
def hello_standalone(username):
    return 'Hello ' + escape_html(username)

def escape_html(text):
    if text is None:
        return None
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;')
                .replace('/', '&#x2F;'))

if __name__ == '__main__':
    # Test cases
    print(hello_standalone("John"))
    print(hello_standalone("Alice"))
    print(hello_standalone("<script>alert('XSS')</script>"))
    print(hello_standalone("User&Name"))
    print(hello_standalone("Test'User\"123"))
