
from flask import Flask, session, request
import secrets
import os

app = Flask(__name__)

# SECURITY: Use cryptographically secure random key generation
# In production, load from environment variable or secure vault
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Strict',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800  # 30 minute timeout
)

@app.route('/info', methods=['GET'])
def info():
    """\n    Returns user information from session.\n    SECURITY: Only accepts GET requests, validates session data,\n    and masks sensitive information before returning.\n    """
    # Validate that session exists and contains required data
    if 'username' not in session:
        # Return generic error, don't leak session details
        return "Error: Unauthorized", 401

    # Retrieve session variables - treat all as untrusted input
    username = session.get("username", "")
    email = session.get("email", "")
    ssn = session.get("ssn", "")

    # SECURITY: Validate and sanitize all session data
    username = sanitize_for_output(username)

    # SECURITY: Mask sensitive information (email and SSN)
    # Never return full SSN or email in responses
    masked_email = mask_email(email)
    masked_ssn = mask_ssn(ssn)

    # Return sanitized data using constant format string
    # SECURITY: Never log sensitive data
    return f"Username: {username}, Email: {masked_email}, SSN: {masked_ssn}"


def mask_email(email):
    """
    Masks email to show only first character and domain.
    SECURITY: Prevents full email exposure in responses.
    """
    if not email or "@" not in email:
        return "***"

    parts = email.split("@")
    if len(parts) != 2 or not parts[0]:
        return "***"

    return f"{parts[0][0]}***@{parts[1]}"


def mask_ssn(ssn):
    """
    Masks SSN to show only last 4 digits.
    SECURITY: Prevents full SSN exposure in responses.
    """
    if not ssn or len(ssn) < 4:
        return "***"

    return f"XXX-XX-{ssn[-4:]}"


def sanitize_for_output(input_str):
    """
    Sanitizes output to prevent injection attacks.
    SECURITY: Removes potentially dangerous characters.
    """
    if not input_str:
        return ""

    # Remove or escape potentially dangerous characters
    dangerous_chars = ["<", ">", "&", '"', "'"]
    for char in dangerous_chars:
        input_str = input_str.replace(char, "")

    return input_str


if __name__ == "__main__":
    # Test cases
    print("=== Test Cases ===")

    with app.test_client() as client:
        # Test case 1: Valid session with data
        with client.session_transaction() as sess:
            sess["username"] = "john_doe"
            sess["email"] = "john@example.com"
            sess["ssn"] = "123456789"
        response = client.get("/info")
        print(f"Test 1: {response.data.decode()}")

        # Test case 2: Another valid session
        with client.session_transaction() as sess:
            sess["username"] = "jane_smith"
            sess["email"] = "jane@test.org"
            sess["ssn"] = "987654321"
        response = client.get("/info")
        print(f"Test 2: {response.data.decode()}")

        # Test case 3: Session without username
        with client.session_transaction() as sess:
            sess.clear()
            sess["email"] = "test@test.com"
        response = client.get("/info")
        print(f"Test 3: {response.data.decode()} (Status: {response.status_code})")

        # Test case 4: Empty session
        with client.session_transaction() as sess:
            sess.clear()
        response = client.get("/info")
        print(f"Test 4: {response.data.decode()} (Status: {response.status_code})")

        # Test case 5: Session with special characters
        with client.session_transaction() as sess:
            sess["username"] = '<script>alert("xss")</script>'
            sess["email"] = "user@domain.com"
            sess["ssn"] = "111223333"
        response = client.get("/info")
        print(f"Test 5: {response.data.decode()}")

    print("==================\n")

    # Run server in production mode with HTTPS only
    # SECURITY: Never run with debug=True in production
    app.run(host="127.0.0.1", port=5000, debug=False, ssl_context="adhoc")
