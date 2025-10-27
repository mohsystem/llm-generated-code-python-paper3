from typing import BinaryIO
import io

MAX_INPUT_BYTES = 4096
MAX_USERNAME_LEN = 64

def _sanitize_username(s: str) -> str:
    if s is None:
        return ""
    out_chars = []
    for ch in s:
        if len(out_chars) >= MAX_USERNAME_LEN:
            break
        # Allow printable ASCII safe set: letters, digits, space, underscore, hyphen, dot
        o = ord(ch)
        if 0x20 <= o <= 0x7E and (ch.isalnum() or ch in " _-."):
            out_chars.append(ch)
    username = "".join(out_chars).strip()
    return username

def http_hello_page(request: BinaryIO, response: BinaryIO) -> None:
    if request is None or response is None:
        raise ValueError("Invalid stream")
    data = request.read(MAX_INPUT_BYTES)
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Request must be binary data")
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    # Use first line only
    first_line = text.splitlines()[0] if text.splitlines() else text
    username = _sanitize_username(first_line)
    if not username:
        username = "user"
    out = f"hello {username}".encode("utf-8")
    response.write(out)
    response.flush()

def _run_test(username: str) -> None:
    req = io.BytesIO(username.encode("utf-8"))
    resp = io.BytesIO()
    http_hello_page(req, resp)
    print(resp.getvalue().decode("utf-8"))

if __name__ == "__main__":
    # Test 1
    _run_test("alice")
    # Test 2
    _run_test("Bob-123")
    # Test 3: injection attempt
    _run_test("eve\r\nSet-Cookie: x=1")
    # Test 4: long input
    _run_test("x" * 200)
    # Test 5: special chars and unicode
    _run_test("张伟/..\\;|$")