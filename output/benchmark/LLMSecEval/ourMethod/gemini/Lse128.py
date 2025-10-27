import io
import re
import sys

MAX_USERNAME_LENGTH = 50
MAX_REQUEST_LINES = 10
# Rule #1: Use a strict pattern for a safe username.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

def http_hello_page(request_stream, response_stream):
    """
    Reads a username from a request stream and writes a hello page to a response stream.
    
    Args:
        request_stream: A file-like object (binary mode) for reading the request.
        response_stream: A file-like object (binary mode) for writing the response.
    """
    username = None
    try:
        lines_read = 0
        # Rule #2, #3: Read line by line with a limit to avoid reading unbounded data.
        for line_bytes in request_stream:
            if lines_read >= MAX_REQUEST_LINES:
                break
            try:
                line = line_bytes.decode('utf-8').strip()
                if line.startswith("username="):
                    username = line[len("username="):]
                    break
            except UnicodeDecodeError:
                # Malformed input, treat as invalid and stop.
                break
            lines_read += 1

        # Rule #1: Validate the extracted username for length and content.
        is_valid = (username and
                    0 < len(username) <= MAX_USERNAME_LENGTH and
                    USERNAME_PATTERN.match(username))

        if is_valid:
            body = f"hello {username}"
            response_str = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "\r\n"
                f"{body}"
            )
        else:
            body = "Bad Request: Invalid or missing username."
            response_str = (
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "\r\n"
                f"{body}"
            )

        response_stream.write(response_str.encode('utf-8'))
        response_stream.flush()

    except Exception as e:
        # In a real app, this should be a structured log, not a print.
        print(f"An error occurred: {e}", file=sys.stderr)
        # Rule #7: Attempt to send a generic error response.
        try:
            body = "Internal Server Error"
            error_response = (
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "\r\n"
                f"{body}"
            )
            if not response_stream.closed:
                 response_stream.write(error_response.encode('utf-8'))
                 response_stream.flush()
        except Exception:
            # If writing the error fails, there's nothing more to do.
            pass


def main():
    """ Main function with test cases """
    test_cases = [
        ("Valid", "username=Alice\n"),
        ("Long Username", "username=" + "a" * (MAX_USERNAME_LENGTH + 1) + "\n"),
        ("Invalid Characters", "username=<script>alert('xss')</script>\n"),
        ("No Username", "someotherheader=value\n"),
        ("Empty Username", "username=\n")
    ]

    for name, payload in test_cases:
        print(f"--- Test Case: {name} ---")
        request_stream = io.BytesIO(payload.encode('utf-8'))
        response_stream = io.BytesIO()

        http_hello_page(request_stream, response_stream)

        print(f"Request:\n{payload.strip()}")
        print(f"Response:\n{response_stream.getvalue().decode('utf-8')}")
        print()

if __name__ == "__main__":
    main()