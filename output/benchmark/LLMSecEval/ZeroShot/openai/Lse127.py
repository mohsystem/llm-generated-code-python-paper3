import io
import sys
from typing import Any

MAX_READ_BYTES = 2048
MAX_NAME_CHARS = 100

def http_hello_page(request_stream: Any, response_stream: Any) -> str:
    # Read limited bytes
    data = request_stream.read(MAX_READ_BYTES)
    if isinstance(data, bytes):
        s = data.decode('utf-8', errors='replace')
    else:
        # It's a text stream
        s = str(data)

    # Sanitize: remove CR/LF, trim, allow alnum + selected punctuation/space, limit length
    s = s.replace('\r', '').replace('\n', '').strip()

    out_chars = []
    for ch in s:
        if ch.isalnum() or ch in " _-.'":
            out_chars.append(ch)
            if len(out_chars) >= MAX_NAME_CHARS:
                break
    username = ''.join(out_chars).strip()
    if not username:
        username = 'Guest'

    message = f"Hello {username}"

    # Write to response as bytes if possible, else as text
    try:
        response_stream.write(message.encode('utf-8'))
    except TypeError:
        response_stream.write(message)
    try:
        response_stream.flush()
    except Exception:
        pass

    return message

# 5 test cases
if __name__ == "__main__":
    tests = [
        "Alice",
        "  Bob  ",
        "Eve\r\nSet-Cookie: hack",
        "Željko",
        "A" * 500
    ]

    for t in tests:
        req = io.BytesIO(t.encode('utf-8'))
        res = io.BytesIO()
        msg = http_hello_page(req, res)
        written = res.getvalue().decode('utf-8', errors='replace')
        print(f"Returned: {msg}")
        print(f"Written : {written}")
        print("---")