from typing import BinaryIO

MAX_INPUT_BYTES = 2048
MAX_USERNAME_CHARS = 64

def http_hello_page(request: BinaryIO, response: BinaryIO) -> str:
    if request is None or response is None:
        raise ValueError("Invalid stream")

    # Read up to first newline or MAX_INPUT_BYTES
    remaining = MAX_INPUT_BYTES
    chunks = []
    while remaining > 0:
        to_read = min(256, remaining)
        data = request.read(to_read)
        if not data:
            break
        # Stop at first newline
        nl_pos = data.find(b'\n')
        cr_pos = data.find(b'\r')
        cut = -1
        if nl_pos != -1 and cr_pos != -1:
            cut = min(nl_pos, cr_pos)
        elif nl_pos != -1:
            cut = nl_pos
        elif cr_pos != -1:
            cut = cr_pos
        if cut != -1:
            chunks.append(data[:cut])
            break
        chunks.append(data)
        remaining -= len(data)
        if remaining <= 0:
            break

    raw = b"".join(chunks).decode("utf-8", errors="ignore")

    # Sanitize: allow [A-Za-z0-9 _.-'], collapse spaces, trim, and limit length
    clean_chars = []
    last_was_space = True  # to trim leading space
    for ch in raw:
        if len(clean_chars) >= MAX_USERNAME_CHARS:
            break
        allowed = ('A' <= ch <= 'Z') or ('a' <= ch <= 'z') or ('0' <= ch <= '9') or ch in "_-.'"
        if allowed:
            clean_chars.append(ch)
            last_was_space = False
        elif ch.isspace():
            if not last_was_space and len(clean_chars) < MAX_USERNAME_CHARS:
                clean_chars.append(' ')
            last_was_space = True
        else:
            # Drop disallowed
            pass

    if clean_chars and clean_chars[-1] == ' ':
        clean_chars.pop()

    username = "".join(clean_chars) if clean_chars else "user"
    response_body = f"Hello {username}"

    response.write(response_body.encode("utf-8"))
    response.flush()
    return response_body


if __name__ == "__main__":
    import io

    tests = [
        b"Alice",
        b"  Bob   Smith  \r\n",
        b"Eve<script>alert(1)</script>",
        b"",
        b"X" * 500,
    ]

    for t in tests:
        req = io.BytesIO(t)
        resp = io.BytesIO()
        result = http_hello_page(req, resp)
        written = resp.getvalue().decode("utf-8", errors="strict")
        print("Returned:", result)
        print("Written: ", written)
        print("---")