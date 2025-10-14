# Note: The 'flask' library needs to be installed.
# You can install it by running: pip install Flask
from flask import Flask, request, render_template_string
import html  # For escaping user input to prevent XSS attacks

app = Flask(__name__)

# In Python with Flask, the 'app' object and its routed functions serve the purpose
# of a main class and methods. We wrap them in a class for organizational
# structure to match the prompt's request for a 'Task38' class.
class Task38:
    def __init__(self):
        # Assign routes to methods
        app.route('/', methods=['GET'])(self.show_form)
        app.route('/submit', methods=['POST'])(self.display_input)

    def show_form(self):
        """
        This function is the handler for the root URL.
        It doesn't accept parameters directly but returns the HTML form as output.
        """
        form_html = """
        <!doctype html>
        <html lang="en">
          <head>
            <title>Input Form</title>
          </head>
          <body>
            <h1>Enter some text</h1>
            <form action="/submit" method="post">
              <label for="userInput">Your Input:</label><br>
              <input type="text" id="userInput" name="userInput" placeholder="Enter text here...">
              <br><br>
              <input type="submit" value="Submit">
            </form>
          </body>
        </html>
        """
        return render_template_string(form_html)

    def display_input(self):
        """
        This function handles the form submission.
        It accepts input via the Flask 'request' object and returns an HTML page
        displaying that input.
        """
        # Get user input from the form
        user_input = request.form.get('userInput', 'No input provided')
        
        # Escape the input to prevent HTML injection (a security measure)
        escaped_input = html.escape(user_input)

        result_html = """
        <!doctype html>
        <html lang="en">
          <head>
            <title>Submission Result</title>
          </head>
          <body>
            <h1>You submitted:</h1>
            <p>{{ user_text }}</p>
            <a href="/">Go back</a>
          </body>
        </html>
        """
        return render_template_string(result_html, user_text=escaped_input)
    
    def run_server(self, host='127.0.0.1', port=5000):
        """Starts the Flask development server."""
        print(f"Server starting. Open http://{host}:{port} in your browser.")
        app.run(host=host, port=port)

# Main execution block
if __name__ == '__main__':
    # "5 test cases" for a web application involve running the server and testing in a browser.
    # How to Test:
    # 1. Make sure you have Flask installed: pip install Flask
    # 2. Run this python script from your terminal: python your_script_name.py
    # 3. Open a web browser and go to http://127.0.0.1:5000
    # 4. You will see a form.
    # 5. Test Case 1: Enter "Hello World" and submit.
    # 6. Test Case 2: Enter "Python Web App" and submit.
    # 7. Test Case 3: Enter an empty string and submit.
    # 8. Test Case 4: Enter "12345" and submit.
    # 9. Test Case 5: Enter "Special Characters: &<>" and submit.
    
    web_app = Task38()
    web_app.run_server()