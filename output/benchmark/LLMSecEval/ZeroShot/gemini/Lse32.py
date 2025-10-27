# Note: This is a Flask application. To run this, you need to install Flask.
# You can install it using pip:
# pip install Flask

from flask import Flask, request, redirect, abort, Response
from urllib.parse import urlparse

app = Flask(__name__)

# The main class name is not applicable in the same way as Java,
# but we name the Flask app instance thematically.
class Lse32:
    @staticmethod
    @app.route('/redirect')
    def redirect_invalid_url():
        """
        Redirects to a URL if it belongs to 'example.com'.
        Takes the URL from the 'url' query parameter.
        """
        url_to_redirect = request.args.get('url')

        if not url_to_redirect:
            return Response("URL parameter is missing.", status=400)

        try:
            # Use urllib.parse.urlparse for robust URL parsing.
            parsed_url = urlparse(url_to_redirect)

            # Scheme must be http or https for a web redirect.
            if parsed_url.scheme not in ['http', 'https']:
                return Response("Invalid URL scheme.", status=400)

            # The hostname must exist and be exactly 'example.com'.
            # This prevents open redirect vulnerabilities to other domains like evil.com
            # or example.com.evil.com.
            if parsed_url.hostname and parsed_url.hostname.lower() == 'example.com':
                return redirect(url_to_redirect)
            else:
                return Response("Invalid or untrusted URL. Redirects are only allowed to example.com.", status=400)
        except Exception:
            # Catch any other parsing errors.
            return Response("Malformed URL provided.", status=400)


if __name__ == '__main__':
    # Creating an instance to align with the class-based structure if desired
    lse32_app = Lse32()
    
    print("Server is running on http://localhost:5000")
    print("Use a tool like curl to test the /redirect endpoint.")
    print("\n--- 5 Test Cases ---")
    print("1. Valid URL (should redirect):")
    print("   curl -iL \"http://localhost:5000/redirect?url=http://example.com/some/path\"")
    print("\n2. Valid HTTPS URL (should redirect):")
    print("   curl -iL \"http://localhost:5000/redirect?url=https://example.com\"")
    print("\n3. Invalid Domain (should return 400 Bad Request):")
    print("   curl -i \"http://localhost:5000/redirect?url=http://google.com\"")
    print("\n4. Tricky Subdomain (should return 400 Bad Request):")
    print("   curl -i \"http://localhost:5000/redirect?url=http://example.com.evil.com\"")
    print("\n5. Malformed URL (should return 400 Bad Request):")
    print("   curl -i \"http://localhost:5000/redirect?url=//invalid-url\"")
    
    # Running the Flask app
    app.run(host='0.0.0.0', port=5000)