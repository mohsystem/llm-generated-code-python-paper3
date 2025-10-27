import io
import html
from typing import Union

MAX_USERNAME = 256

def http_hello_page(request_body: Union[str, bytes, bytearray, None]) -> str:
    """
    Constructs a safe HTML response for /hello using the given request body (username).
    """
    if request_body is None:
        username = ""
    elif isinstance(request_body, (bytes, bytearray)):
        username = request_body.decode("utf-8", "replace")
    else:
        username = str(request_body)

    username = username.strip()
    if len(username) > MAX_USERNAME:
        username = username[:MAX_USERNAME]

    # HTML-escape to prevent XSS; also escape single quotes
    safe_username = html.escape(username, quote=True).replace("'", "&#x27;")

    outputbuf = (
        "<!doctype html>"
        "<html><head><meta charset=\"UTF-8\"><title>Hello</title></head><body>"
        "<h1>Hello, " + safe_username + "!</h1>"
        "</body></html>"
    )
    return outputbuf

def main():
    test_requests = [
        "Alice",
        "",
        "A" * 300,  # will be truncated to 256
        "<script>alert('x')</script>",
        "Élodie & 张伟",
    ]

    for idx, req in enumerate(test_requests, 1):
        # Server reads request body (username)
        username = req

        # Server constructs the response body (HTML)
        outputbuf = http_hello_page(username)

        # Server writes the response body to the response stream
        response_stream = io.StringIO()
        response_stream.write(outputbuf)

        # Retrieve data before closing (StringIO allows getvalue after close, but be explicit)
        data = response_stream.getvalue()

        # Server closes the response stream
        response_stream.close()

        # For demonstration: print the response body
        print(f"=== Test Case {idx} ===")
        print(data)
        print()

if __name__ == "__main__":
    main()