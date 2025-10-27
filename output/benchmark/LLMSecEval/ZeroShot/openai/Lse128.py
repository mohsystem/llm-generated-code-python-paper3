import io
import re

MAX_INPUT_BYTES = 1024
MAX_USERNAME_CHARS = 100

def http_hello_page(request_stream, response_stream):
    if request_stream is None or response_stream is None:
        raise ValueError("request_stream and response_stream must not be None")

    data = request_stream.read(MAX_INPUT_BYTES)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("request_stream must be a binary stream returning bytes")
    text = data.decode('utf-8', errors='replace')

    username = sanitize_username(text)
    output = f"hello {username}"

    response_stream.write(output.encode('utf-8'))
    if hasattr(response_stream, "flush"):
        response_stream.flush()

    return output

def sanitize_username(s):
    if s is None:
        return "anonymous"
    # Remove CR and LF
    s = s.replace('\r', '').replace('\n', '')
    # Keep only allowed chars and limit length
    s = re.sub(r'[^A-Za-z0-9 _.\-@]', '', s)[:MAX_USERNAME_CHARS].strip()
    return s if s else "anonymous"

if __name__ == "__main__":
    tests = [
        b"Alice",
        b"Bob<script>alert(1)</script>",
        b"Carol\r\nSet-Cookie: session=evil",
        "Δelta-用户".encode("utf-8"),
        b"Dave ../../etc/passwd\t\n",
    ]
    for i, t in enumerate(tests, 1):
        req = io.BytesIO(t)
        resp = io.BytesIO()
        result = http_hello_page(req, resp)
        written = resp.getvalue().decode('utf-8', errors='replace')
        print(f"Test {i}: {result} | ResponseStream: {written}")